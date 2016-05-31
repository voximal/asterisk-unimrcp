/*
 * Asterisk -- An open source telephony toolkit.
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *
 * Please follow coding guidelines 
 * http://svn.digium.com/view/asterisk/trunk/doc/CODING-GUIDELINES
 */

/*! \file
 *
 * \brief Implementation of the Asterisk's Speech API via UniMRCP
 *
 * \author Arsen Chaloyan arsen.chaloyan@unimrcp.org
 * 
 * \ingroup applications
 */

/* Asterisk includes. */
#include "ast_compat_defs.h"

#define AST_MODULE "res_speech_unimrcp" 
ASTERISK_FILE_VERSION(__FILE__, "$Revision: 1.74 $")

#include <asterisk/module.h>
#include <asterisk/config.h>
#include <asterisk/frame.h>
#include <asterisk/speech.h>

#include <apr_thread_cond.h>
#include <apr_thread_proc.h>
#include <apr_tables.h>
#include <apr_hash.h>
#include <unimrcp_client.h>
#include <mrcp_application.h>
#include <mrcp_message.h>
#include <mrcp_generic_header.h>
#include <mrcp_recog_header.h>
#include <mrcp_recog_resource.h>
#include <mpf_frame_buffer.h>
#include <mpf_engine.h>
#include <mpf_codec_manager.h>
#include <mpf_dtmf_generator.h>
#include <mpf_rtp_termination_factory.h>
#include <apt_nlsml_doc.h>
#include <apt_pool.h>
#include <apt_log.h>



#define UNI_ENGINE_NAME "unimrcp"
#define UNI_ENGINE_CONFIG "res-speech-unimrcp.conf"

/* Force uniMRCP directory */
#ifdef UNIMRCP_DIR_LOCATION
#undef UNIMRCP_DIR_LOCATION
#endif
#define UNIMRCP_DIR_LOCATION "/usr/local/unimrcp"

/** Timeout to wait for asynchronous response (actually this timeout shouldn't expire) */
#define MRCP_APP_REQUEST_TIMEOUT 60 * 1000000

/** \brief Forward declaration of speech */
typedef struct uni_speech_t uni_speech_t;
/** \brief Forward declaration of engine */
typedef struct uni_engine_t uni_engine_t;

/** \brief Declaration of UniMRCP based speech structure */
struct uni_speech_t {
	/* Name of the speech object to be used for logging */
	const char            *name;
	/* Client session */
	mrcp_session_t        *session;
	/* Client channel */
	mrcp_channel_t        *channel;
	/* UniMRCP stream object. */
	mpf_audio_stream_t *stream;
	/* Asterisk speech base */
	struct ast_speech     *speech_base;

	/* Conditional wait object */
	apr_thread_cond_t     *wait_object;
	/* Mutex of the wait object */
	apr_thread_mutex_t    *mutex;

	/* Buffer of media frames */
	mpf_frame_buffer_t    *media_buffer;

	/* Active grammars (Content-IDs) */
	apr_hash_t            *active_grammars;

	/* Binary grammars (Content-IDs) */
	apr_hash_t            *binary_grammars;

	/* MRCP properties (header fields) loaded from grammarload */
	mrcp_message_header_t *properties;

  /* Language */
	char                  language[50];

	/* Is session management request in-progress or not */
	apt_bool_t             is_sm_request;
	/* Session management request sent to server */
	mrcp_sig_command_e     sm_request;
	/* Satus code of session management response */
	mrcp_sig_status_code_e sm_response;

	/* Is recognition in-progress or not */
	apt_bool_t             is_inprogress;
	
	/* In-progress request sent to server */
	mrcp_message_t        *mrcp_request;
	/* Response received from server */
	mrcp_message_t        *mrcp_response;
	/* Event received from server */
	mrcp_message_t        *mrcp_event;

  /* UniMRCP DTMF digit generator. */
	mpf_dtmf_generator_t  *dtmf_generator;
};

/** \brief Declaration of UniMRCP based recognition engine */
struct uni_engine_t {
	/* Memory pool */
	apr_pool_t            *pool;
	/* Client stack instance */
	mrcp_client_t         *client;
	/* Application instance */
	mrcp_application_t    *application;

	/* Profile name */
	const char            *profile;
	/* Log level */
	apt_log_priority_e     log_level;
	/* Log output */
	apt_log_output_e       log_output;

	/* Grammars to be preloaded with each MRCP session, if specified in config [grammars] */
	apr_table_t           *grammars;
	/* MRCPv2 properties (header fields) loaded from config */
	mrcp_message_header_t *v2_properties;
	/* MRCPv1 properties (header fields) loaded from config */
	mrcp_message_header_t *v1_properties;

	/* Mutex to be used for speech object numbering */
	apr_thread_mutex_t    *mutex;
	/* Current speech object number. */
	apr_uint16_t           current_speech_index;

	/* Current speech sessions. */
	apr_uint16_t           current_speech_sessions;
	/* Max speech sessions. */
	apr_uint16_t           max_speech_sessions;


	/* Options for ASR providers */
  apt_bool_t cancelifqueue; // option for Vestec
  apt_bool_t startinputtimers;
  apt_bool_t dtmfstopspeech;
  apt_bool_t returnnlsml;
  apt_bool_t vendorspecificparameters; // option for Nuance
  apt_bool_t setparams; // option for Nuance
  apt_bool_t removeswi; // option for Nuance
  apt_bool_t setspeechlanguage; // option for Nuance
  apt_bool_t binarygrammars; // option for Nuance
};

static struct uni_engine_t uni_engine;

static int uni_recog_create_internal(struct ast_speech *speech, ast_format_compat *format);
static apt_bool_t uni_recog_channel_create(uni_speech_t *uni_speech, ast_format_compat *format);
static apt_bool_t uni_recog_properties_set(uni_speech_t *uni_speech);
static apt_bool_t uni_recog_start_input_timers(uni_speech_t *uni_speech);
static apt_bool_t uni_recog_grammars_preload(uni_speech_t *uni_speech);
static apt_bool_t uni_recog_sm_request_send(uni_speech_t *uni_speech, mrcp_sig_command_e sm_request);
static apt_bool_t uni_recog_mrcp_request_send(uni_speech_t *uni_speech, mrcp_message_t *message);
static void uni_recog_cleanup(uni_speech_t *uni_speech);



/** \brief Backward compatible define for the const qualifier */
#if AST_VERSION_AT_LEAST(1,8,0)
#define ast_compat_const const
#else /* < 1.8 */
#define ast_compat_const
#endif

/** \brief Get next speech identifier to be used for logging */
static apr_uint16_t uni_speech_id_get()
{
	apr_uint16_t id;

	if(uni_engine.mutex) apr_thread_mutex_lock(uni_engine.mutex);

	id = uni_engine.current_speech_index;

	if (uni_engine.current_speech_index == APR_UINT16_MAX)
		uni_engine.current_speech_index = 0;
	else
		uni_engine.current_speech_index++;

	if(uni_engine.mutex) apr_thread_mutex_unlock(uni_engine.mutex);

	return id;
}


/** \brief Version dependent prototypes of uni_recog_create() function */
#if AST_VERSION_AT_LEAST(10,0,0)
static int uni_recog_create(struct ast_speech *speech, ast_format_compat *format)
{
	return uni_recog_create_internal(speech,format);
}
#elif AST_VERSION_AT_LEAST(1,6,0)
static int uni_recog_create(struct ast_speech *speech, int format_id)
{
	ast_format_compat format;
	ast_format_clear(&format);
	format.id = format_id;
	return uni_recog_create_internal(speech,&format);
}
#else /* 1.4 */
static int uni_recog_create(struct ast_speech *speech)
{
	ast_format_compat format;
	ast_format_clear(&format);
	format.id = 0;
	return uni_recog_create_internal(speech,&format);
}
#endif

/** \brief Set up the speech structure within the engine */
static int uni_recog_create_internal(struct ast_speech *speech, ast_format_compat *format)
{
	uni_speech_t *uni_speech;
	mrcp_session_t *session;
	apr_pool_t *pool;
	const mpf_codec_descriptor_t *descriptor;
  const char *profile = NULL;

  if(uni_engine.mutex) apr_thread_mutex_lock(uni_engine.mutex);

  profile = strchr(speech->engine->name, ':');
  if (!profile)
  profile = uni_engine.profile;
  else
  profile++;

	/* Create session instance */
	session = mrcp_application_session_create(uni_engine.application, profile, speech);
	if(!session) {
		ast_log(LOG_ERROR, "Failed to create MRCP session\n");
		return -1;
	}

	if (uni_engine.current_speech_sessions >= uni_engine.max_speech_sessions)
	{
		ast_log(LOG_ERROR, "Too much MRCP session running!\n");
  	if(uni_engine.mutex) apr_thread_mutex_unlock(uni_engine.mutex);
		return -1;
	}
	else
	{
    uni_engine.current_speech_sessions++;

		ast_log(LOG_DEBUG, "Speech sessions :%d/%d\n",
		 uni_engine.current_speech_sessions,
		 uni_engine.max_speech_sessions);
	}

	if(uni_engine.mutex) apr_thread_mutex_unlock(uni_engine.mutex);

	pool = mrcp_application_session_pool_get(session);
	uni_speech = apr_palloc(pool,sizeof(uni_speech_t));
	uni_speech->name = apr_psprintf(pool, "RSU-%hu", uni_speech_id_get());
	uni_speech->session = session;
  uni_speech->stream = NULL;
	uni_speech->channel = NULL;
	uni_speech->wait_object = NULL;
	uni_speech->mutex = NULL;
	uni_speech->media_buffer = NULL;
	uni_speech->active_grammars = apr_hash_make(pool);
	uni_speech->binary_grammars = apr_hash_make(pool);
	uni_speech->is_sm_request = FALSE;
	uni_speech->is_inprogress = FALSE;
	uni_speech->sm_request = 0;
	uni_speech->sm_response = MRCP_SIG_STATUS_CODE_SUCCESS;
	uni_speech->mrcp_request = NULL;
	uni_speech->mrcp_response = NULL;
	uni_speech->mrcp_event = NULL;
	uni_speech->properties = NULL;
	uni_speech->language[0] = 0;
  uni_speech->dtmf_generator = NULL;

	uni_speech->speech_base = speech;
	speech->data = uni_speech;

	/* Create cond wait object and mutex */
	apr_thread_mutex_create(&uni_speech->mutex,APR_THREAD_MUTEX_DEFAULT,pool);
	apr_thread_cond_create(&uni_speech->wait_object,pool);

	ast_log(LOG_NOTICE, "(%s) Create speech resource\n",uni_speech->name);

	/* Set session name for logging purposes. */
	mrcp_application_session_name_set(session,uni_speech->name);

	/* Create recognition channel instance */
	if(uni_recog_channel_create(uni_speech,format) != TRUE) {
		ast_log(LOG_ERROR, "(%s) Failed to create MRCP channel\n",uni_speech->name);
		uni_recog_cleanup(uni_speech);
		return -1;
	}

	/* Send add channel request and wait for response */
	if(uni_recog_sm_request_send(uni_speech,MRCP_SIG_COMMAND_CHANNEL_ADD) != TRUE) {
		ast_log(LOG_WARNING, "(%s) Failed to send add-channel request\n",uni_speech->name);
		uni_recog_cleanup(uni_speech);
		return -1;
	}

	/* Check received response */
	if(uni_speech->sm_response != MRCP_SIG_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "(%s) Failed to add MRCP channel status: %d\n",uni_speech->name,uni_speech->sm_response);
		uni_recog_sm_request_send(uni_speech,MRCP_SIG_COMMAND_SESSION_TERMINATE);
		uni_recog_cleanup(uni_speech);
		return -1;
	}

	descriptor = mrcp_application_source_descriptor_get(uni_speech->channel);
	if(descriptor) {
		mpf_frame_buffer_t *media_buffer;
		apr_size_t frame_size = mpf_codec_linear_frame_size_calculate(descriptor->sampling_rate,descriptor->channel_count);
		/* Create media buffer */
		ast_log(LOG_DEBUG, "(%s) Create media buffer frame_size:%"APR_SIZE_T_FMT"\n",uni_speech->name,frame_size);
		media_buffer = mpf_frame_buffer_create(frame_size,20,pool);
		uni_speech->media_buffer = media_buffer;
	}

	if(!uni_speech->media_buffer) {
		ast_log(LOG_WARNING, "(%s) Failed to create media buffer\n",uni_speech->name);
		uni_recog_sm_request_send(uni_speech,MRCP_SIG_COMMAND_SESSION_TERMINATE);
		uni_recog_cleanup(uni_speech);
		return -1;
	}



	/* Set properties for session */
	uni_recog_properties_set(uni_speech);
	/* Preload grammars */
	uni_recog_grammars_preload(uni_speech);
	return 0;
}

/** \brief Destroy any data set on the speech structure by the engine */
static int uni_recog_destroy(struct ast_speech *speech)
{
	uni_speech_t *uni_speech = speech->data;

	if (!uni_speech)
	return -1;

  ast_log(LOG_NOTICE, "(%s) Destroy speech resource\n",uni_speech->name);

	/* Terminate session first */
	uni_recog_sm_request_send(uni_speech,MRCP_SIG_COMMAND_SESSION_TERMINATE);
	/* Then cleanup it */
	uni_recog_cleanup(uni_speech);
	return 0;
}

/*! \brief Cleanup already allocated data */
static void uni_recog_cleanup(uni_speech_t *uni_speech)
{
  ast_log(LOG_DEBUG, "(%s) Clean up recognition\n",uni_speech->name);

	if (uni_speech->properties)
	{
    mrcp_message_header_destroy(uni_speech->properties);
    uni_speech->properties = NULL;
	}

	if(uni_speech->speech_base) {
		uni_speech->speech_base->data = NULL;
	}
	if(uni_speech->mutex) {
		apr_thread_mutex_destroy(uni_speech->mutex);
		uni_speech->mutex = NULL;
	}
	if(uni_speech->wait_object) {
		apr_thread_cond_destroy(uni_speech->wait_object);
		uni_speech->wait_object = NULL;
	}
	if(uni_speech->media_buffer) {
		mpf_frame_buffer_destroy(uni_speech->media_buffer);
		uni_speech->media_buffer = NULL;
	}

	if (uni_speech->session) {
	  if (uni_speech->speech_base)
    mrcp_application_session_object_set(uni_speech->session, NULL);
		else
		{
      ast_log(LOG_DEBUG, "(%s) Destroy application session\n", uni_speech->name);
  		mrcp_application_session_destroy(uni_speech->session);
		}

    uni_speech->session = NULL;
	}

  if (uni_speech->speech_base)
	{
	  uni_speech->speech_base->data = NULL;
	  uni_speech->speech_base = NULL;
	}
}

/*! \brief Stop the in-progress recognition */
static int uni_recog_stop(struct ast_speech *speech)
{
	uni_speech_t *uni_speech = speech->data;
	mrcp_message_t *mrcp_message;

	if (uni_speech->properties)
	{

	}
	
	if(!uni_speech->is_inprogress) {
		return 0;
	}

  ast_log(LOG_NOTICE, "(%s) Stop recognition\n",uni_speech->name);
	mrcp_message = mrcp_application_message_create(
								uni_speech->session,
								uni_speech->channel,
								RECOGNIZER_STOP);
	if(!mrcp_message) {
		ast_log(LOG_WARNING, "(%s) Failed to create MRCP message\n",uni_speech->name);
		return -1;
	}
	
	/* Reset last event (if any) */
	uni_speech->mrcp_event = NULL;

	/* Send MRCP request and wait for response */
	if(uni_recog_mrcp_request_send(uni_speech,mrcp_message) != TRUE) {
    ast_log(LOG_WARNING, "(%s) Failed to stop recognition\n",uni_speech->name);
		return -1;
	}

	/* Check received response */
	if(!uni_speech->mrcp_response || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "Received failure response\n");
		return -1;
	}
	
	/* Reset media buffer */
	mpf_frame_buffer_restart(uni_speech->media_buffer);
	
	ast_speech_change_state(speech, AST_SPEECH_STATE_NOT_READY);
	
	uni_speech->is_inprogress = FALSE;
	return 0;
}

/*! \brief Load a local grammar on the speech structure */
static int uni_recog_load_grammar(struct ast_speech *speech, ast_compat_const char *grammar_name, ast_compat_const char *grammar_path)
{
	uni_speech_t *uni_speech = speech->data;
	mrcp_message_t *mrcp_message;
	mrcp_generic_header_t *generic_header;
	const char *content_type = NULL;
	apt_bool_t inline_content = FALSE;
	char *tmp;
	apr_file_t *file;
	apt_str_t *body = NULL;
	int prop = 0;
  apr_pool_t *pool = mrcp_application_session_pool_get(uni_speech->session);
  const char *key;
  char *val;

  if (uni_engine.binarygrammars)
  if (!strncmp(grammar_path, "uri:", 4))
  if (strstr(grammar_path, ".gram") || strstr(grammar_path, ".gout") || strstr(grammar_path, ".grbin"))
  {
    grammar_path+=4;

    ast_log(LOG_DEBUG, "(%s) Load binary grammar: %s (%s)\n",uni_speech->name,grammar_name, grammar_path);
    key = apr_pstrdup(pool,grammar_name);
    val = apr_pstrdup(pool,grammar_path);
	  apr_hash_set(uni_speech->binary_grammars,key,APR_HASH_KEY_STRING,val);

    return 0;
  }

	mrcp_message = mrcp_application_message_create(
								uni_speech->session,
								uni_speech->channel,
								RECOGNIZER_DEFINE_GRAMMAR);
	if(!mrcp_message) {
		ast_log(LOG_WARNING, "(%s) Failed to create MRCP message\n",uni_speech->name);
		return -1;
	}

	/*
	 * Grammar name and path are mandatory attributes, 
	 * grammar type can be optionally specified with path.
	 *
	 * SpeechLoadGrammar(name|path)
	 * SpeechLoadGrammar(name|type:path)
	 * SpeechLoadGrammar(name|uri:path)
	 * SpeechLoadGrammar(name|builtin:grammar/digits)
	 * SpeechLoadGrammar(value|property:name)
	 */

	tmp = strchr(grammar_path,':');
	if(tmp) {
		const char builtin_token[] = "builtin";
		const char uri_token[] = "uri";
		const char property_token[] = "property";
		if(strncmp(grammar_path,builtin_token,sizeof(builtin_token)-1) == 0) {
			content_type = "text/uri-list";
			inline_content = TRUE;
		}
		else if(strncmp(grammar_path,uri_token,sizeof(uri_token)-1) == 0) {
			content_type = "text/uri-list";
			inline_content = TRUE;
			grammar_path = tmp+1;
		}
		else if(strncmp(grammar_path,property_token,sizeof(property_token)-1) == 0) {
			prop = 1;
			inline_content = TRUE;
			grammar_path = tmp+1;
      tmp = strchr(grammar_path,'=');
			if (tmp)
			{
				*tmp = 0;
        grammar_name=tmp+1;
			}

      if(strncmp(grammar_path,"Speech-Language",sizeof("Speech-Language")-1) == 0) {
        uni_speech->language[0]=0;
        ast_log(LOG_DEBUG, "Language grammar properties set :%s.\n", grammar_name);

        if (uni_engine.setspeechlanguage)
        strncpy(uni_speech->language, grammar_name, sizeof(uni_speech->language)-1);
        else
        return 0;
      }
		}
		else {
			*tmp = '\0';
			content_type = grammar_path;
			grammar_path = tmp+1;
		}
	}

	if (prop)
	{
    /* Inherit properties */
		if (uni_speech->properties == NULL)
		{
#if defined(TRANSPARENT_HEADER_FIELDS_SUPPORT)
	    uni_speech->properties = mrcp_message_header_create(
		    mrcp_generic_header_vtable_get(mrcp_message->start_line.version),
		    mrcp_recog_header_vtable_get(mrcp_message->start_line.version),
		    pool);
#else
	    uni_speech->properties = apr_palloc(pool,sizeof(mrcp_message_header_t));
	    mrcp_message_header_init(speech->properties);
	    speech->properties->generic_header_accessor.vtable = mrcp_generic_header_vtable_get(mrcp_message->start_line.version);
    	speech->properties->resource_header_accessor.vtable = mrcp_recog_header_vtable_get(mrcp_message->start_line.version);
    	mrcp_header_allocate(&properties->generic_header_accessor,pool);
	    mrcp_header_allocate(&properties->resource_header_accessor,pool);
#endif
	  }

		if (uni_speech->properties == NULL)
		return -1;

	  /* Check the properties set by loadgrammar */
    if(uni_speech->properties) {
	    apt_header_field_t *header_field;

      ast_log(LOG_DEBUG, "Check grammar properties.\n");

	    for(header_field = APR_RING_FIRST(&uni_speech->properties->header_section.ring);
			  header_field != APR_RING_SENTINEL(&uni_speech->properties->header_section.ring, apt_header_field_t, link);
				  header_field = APR_RING_NEXT(header_field, link)) {

		    /* Dump the content */
        ast_log(LOG_DEBUG, "Dump Property: %s=%s\n", header_field->name.buf, header_field->value.buf);

        if (!strcmp(header_field->name.buf, grammar_path))
			  {
          ast_log(LOG_DEBUG, "Remove property : %s=%s\n", header_field->name.buf, header_field->value.buf);
          apt_header_section_field_remove(&uni_speech->properties->header_section,header_field);
			  }
			}
	  }


  	/* Add properties set by loadgrammar */
#if defined(TRANSPARENT_HEADER_FIELDS_SUPPORT)
		mrcp_header_fields_inherit(&mrcp_message->header,uni_speech->properties,mrcp_message->pool);
#else
		mrcp_message_header_inherit(&mrcp_message->header,uni_speech->properties,mrcp_message->pool);
#endif

#if defined(TRANSPARENT_HEADER_FIELDS_SUPPORT)
	  apt_header_field_t *header_field;

    ast_log(LOG_DEBUG, "load_grammar set property %s=%s\n", grammar_path, grammar_name);

  	header_field = apt_header_field_create_c(grammar_path,grammar_name, pool);
		if(header_field) {
			if(mrcp_header_field_add(uni_speech->properties,header_field, pool) == FALSE) {
				ast_log(LOG_WARNING, "Unknown MRCP header %s=%s\n", grammar_path, grammar_name);
				return -1;
			}
		}
#else
	  apt_pair_t pair;

    ast_log(LOG_DEBUG, "load_grammar set property %s=%s\n", grammar_path, grammar_name);

		apt_string_set(&pair.name,grammar_path);
		apt_string_set(&pair.value,grammar_name);
		if(mrcp_header_parse(&uni_speech->properties->resource_header_accessor,&pair, pool) != TRUE) {
			if(mrcp_header_parse(&uni_speech->properties->generic_header_accessor,&pair, pool) != TRUE) {
				ast_log(LOG_WARNING, "Unknown MRCP header %s=%s\n", grammar_path, grammar_name);
				return -1;
			}
		}
#endif

		return 0;
	}

	if(inline_content == TRUE) {
		body = &mrcp_message->body;
		apt_string_assign(body,grammar_path,mrcp_message->pool);
	}
	else {
		if(apr_file_open(&file,grammar_path,APR_FOPEN_READ|APR_FOPEN_BINARY,0,mrcp_message->pool) == APR_SUCCESS) {
			apr_finfo_t finfo;
			if(apr_file_info_get(&finfo,APR_FINFO_SIZE,file) == APR_SUCCESS) {
				/* Read message body */
				body = &mrcp_message->body;
				body->buf = apr_palloc(mrcp_message->pool,finfo.size+1);
				body->length = (apr_size_t)finfo.size;
				if(apr_file_read(file,body->buf,&body->length) != APR_SUCCESS) {
          ast_log(LOG_WARNING, "(%s) Failed to read grammar file %s\n",uni_speech->name,grammar_path);
				}
				body->buf[body->length] = '\0';
			}
			apr_file_close(file);
		}
		else {
			ast_log(LOG_WARNING, "(%s) No such grammar file available %s\n",uni_speech->name,grammar_path);
			return -1;
		}
	}

	if(!body || !body->buf) {
		ast_log(LOG_WARNING, "(%s) No grammar content available %s\n",uni_speech->name,grammar_path);
		return -1;
	}

	/* Try to implicitly detect content type, if it's not specified */
	if(!content_type) {
		if(strstr(body->buf,"#JSGF")) {
			content_type = "application/x-jsgf";
		}
		else if(strstr(body->buf,"#ABNF")) {
			content_type = "application/srgs";
		}
    else if(!strncmp(body->buf, "SpeechWorks binary", 18)) {
			content_type = "application/x-swi-grammar";
    }
		else {
			content_type = "application/srgs+xml";
		}
	}

	ast_log(LOG_DEBUG, "(%s) Load grammar name: %s type: %s path: %s\n",
				uni_speech->name,
				grammar_name,
				content_type,
				grammar_path);
	/* Get/allocate generic header */
	generic_header = mrcp_generic_header_prepare(mrcp_message);
	if(generic_header) {
		/* Set generic header fields */
		apt_string_assign(&generic_header->content_type,content_type,mrcp_message->pool);
		mrcp_generic_header_property_add(mrcp_message,GENERIC_HEADER_CONTENT_TYPE);
		apt_string_assign(&generic_header->content_id,grammar_name,mrcp_message->pool);
		mrcp_generic_header_property_add(mrcp_message,GENERIC_HEADER_CONTENT_ID);
	}

  if (uni_engine.setspeechlanguage)
  if (uni_speech->language[0])
  {
		ast_log(LOG_DEBUG, "(%s) %s: %s\n", uni_speech->name, "Speech-Language", uni_speech->language);
		apt_header_field_t *header_field = apt_header_field_create_c("Speech-Language", uni_speech->language, mrcp_message->pool);
		if(header_field) {
			if(mrcp_message_header_field_add(mrcp_message, header_field) == FALSE) {
				ast_log(LOG_WARNING, "Error setting MRCP header %s=%s\n", "Speech-Language", uni_speech->language);
			}
		}
  }

	/* Send MRCP request and wait for response */
	if(uni_recog_mrcp_request_send(uni_speech,mrcp_message) != TRUE) {
		ast_log(LOG_WARNING, "(%s) Failed to load grammar\n",uni_speech->name);
		return -1;
	}

	/* Check received response */
	if(!uni_speech->mrcp_response || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "Received failure response\n");
		return -1;
	}
	return 0;
}

/** \brief Unload a local grammar */
static int uni_recog_unload_grammar(struct ast_speech *speech, ast_compat_const char *grammar_name)
{
	uni_speech_t *uni_speech = speech->data;
	mrcp_message_t *mrcp_message;
	mrcp_generic_header_t *generic_header;
  char *binary;

	if(uni_speech->is_inprogress) {
		uni_recog_stop(speech);
	}

	ast_log(LOG_DEBUG, "(%s) Unload grammar name: %s\n",
				uni_speech->name,
				grammar_name);

  binary = apr_hash_get(uni_speech->binary_grammars, grammar_name, APR_HASH_KEY_STRING);
  if (binary)
	{
  	ast_log(LOG_DEBUG, "(%s) Unload binary grammar: %s (%s)\n",uni_speech->name,grammar_name, binary);

  	apr_hash_set(uni_speech->binary_grammars,grammar_name,APR_HASH_KEY_STRING,NULL);
    return 0;
  }

	apr_hash_set(uni_speech->active_grammars,grammar_name,APR_HASH_KEY_STRING,NULL);

	mrcp_message = mrcp_application_message_create(
								uni_speech->session,
								uni_speech->channel,
								RECOGNIZER_DEFINE_GRAMMAR);
	if(!mrcp_message) {
		ast_log(LOG_WARNING, "(%s) Failed to create MRCP message\n",uni_speech->name);
		return -1;
	}
	
	/* Get/allocate generic header */
	generic_header = mrcp_generic_header_prepare(mrcp_message);
	if(generic_header) {
		/* Set generic header fields */
		//apt_string_assign(&generic_header->content_type,"application/srgs",mrcp_message->pool);
		//mrcp_generic_header_property_add(mrcp_message,GENERIC_HEADER_CONTENT_TYPE);
		apt_string_assign(&generic_header->content_id,grammar_name,mrcp_message->pool);
		mrcp_generic_header_property_add(mrcp_message,GENERIC_HEADER_CONTENT_ID);
	}

	/* Send MRCP request and wait for response */
	if(uni_recog_mrcp_request_send(uni_speech,mrcp_message) != TRUE) {
		ast_log(LOG_WARNING, "(%s) Failed to unload grammar\n",uni_speech->name);
		return -1;
	}

	/* Check received response */
	if(!uni_speech->mrcp_response || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "Received failure response\n");
		return -1;
	}
	return 0;
}

/** \brief Activate a loaded grammar */
static int uni_recog_activate_grammar(struct ast_speech *speech, ast_compat_const char *grammar_name)
{
	uni_speech_t *uni_speech = speech->data;
	apr_pool_t *pool = mrcp_application_session_pool_get(uni_speech->session);
	const char *entry;

  // Dump binary grammars
  if (0)
  {
  	apr_hash_index_t *it;
		void *val;
		const void *key;

		/* Construct and set message body */
		it = apr_hash_first(pool,uni_speech->binary_grammars);
		if(it) {
			apr_hash_this(it,&key,NULL,&val);

	  	ast_log(LOG_DEBUG, "(%s) Binary grammar : %s , %s\n", uni_speech->name, (const char*)key, (char*)val);

		it = apr_hash_next(it);
		}
		for(; it; it = apr_hash_next(it)) {
			apr_hash_this(it,&key,NULL,&val);

    	ast_log(LOG_DEBUG, "(%s) Binary grammar : %s , %s\n",uni_speech->name, (const char*)key, (char*)val);
		}
  }

	ast_log(LOG_DEBUG, "(%s) Activate grammar name: %s\n",uni_speech->name,grammar_name);
	entry = apr_pstrdup(pool,grammar_name);
	apr_hash_set(uni_speech->active_grammars,entry,APR_HASH_KEY_STRING,entry);
	return 0;
}

/** \brief Deactivate a loaded grammar */
static int uni_recog_deactivate_grammar(struct ast_speech *speech, ast_compat_const char *grammar_name)
{
	uni_speech_t *uni_speech = speech->data;

	if(uni_speech->is_inprogress) {
		uni_recog_stop(speech);
	}

	ast_log(LOG_NOTICE, "(%s) Deactivate grammar name: %s\n",uni_speech->name,grammar_name);
	apr_hash_set(uni_speech->active_grammars,grammar_name,APR_HASH_KEY_STRING,NULL);
	return 0;
}

/** \brief Write audio to the speech engine */
static int uni_recog_write(struct ast_speech *speech, void *data, int len)
{
	uni_speech_t *uni_speech = speech->data;
	mpf_frame_t frame;

#if 0
	ast_log(LOG_DEBUG, "(%s) Write audio len: %d\n",uni_speech->name,len);
#endif
	frame.type = MEDIA_FRAME_TYPE_AUDIO;
	frame.marker = MPF_MARKER_NONE;
	frame.codec_frame.buffer = data;
	frame.codec_frame.size = len;

	if(mpf_frame_buffer_write(uni_speech->media_buffer,&frame) != TRUE) {
		ast_log(LOG_DEBUG, "(%s) Failed to write audio len: %d\n",uni_speech->name,len);
	}
	return 0;
}

/** \brief Signal DTMF was received */
static int uni_recog_dtmf(struct ast_speech *speech, const char *dtmf)
{
	uni_speech_t *uni_speech = speech->data;
	ast_log(LOG_NOTICE, "(%s) Signal DTMF %s\n",uni_speech->name,dtmf);

  if (uni_speech->dtmf_generator != NULL) {
		char digits[2];
		digits[0] = (char)*dtmf;
		digits[1] = '\0';

		ast_log(LOG_NOTICE, "(%s) DTMF digit queued (%s)\n", uni_speech->name, digits);
		mpf_dtmf_generator_enqueue(uni_speech->dtmf_generator, digits);
	}

	if (uni_engine.dtmfstopspeech)
  if (uni_speech->is_inprogress)
  {
		ast_log(LOG_NOTICE, "(%s) DTMF stop the speech.\n", uni_speech->name);
    uni_recog_stop(speech);
  }

	return 0;
}

/** brief Prepare engine to accept audio */
static int uni_recog_start(struct ast_speech *speech)
{
	uni_speech_t *uni_speech = speech->data;
	mrcp_message_t *mrcp_message;
	mrcp_generic_header_t *generic_header;
	mrcp_recog_header_t *recog_header;
  apr_pool_t *pool = mrcp_application_session_pool_get(uni_speech->session);

  // Dump binary grammars
  {
  	apr_hash_index_t *it;
		void *val;
		const void *key;

		/* Construct and set message body */
		it = apr_hash_first(pool,uni_speech->binary_grammars);
		if(it) {
			apr_hash_this(it,&key,NULL,&val);

	  	ast_log(LOG_DEBUG, "(%s) Binary grammar : %s , %s\n", uni_speech->name, (const char*)key, (char*)val);

		it = apr_hash_next(it);
		}
		for(; it; it = apr_hash_next(it)) {
			apr_hash_this(it,&key,NULL,&val);

    	ast_log(LOG_DEBUG, "(%s) Binary grammar : %s , %s\n",uni_speech->name, (const char*)key, (char*)val);
		}
  }

	if(uni_speech->is_inprogress) {
		if (uni_engine.startinputtimers)
		uni_recog_stop(speech);
	}

  /* Set properties for session */
	if (uni_engine.setparams)
	uni_recog_properties_set(uni_speech);

	if(uni_speech->is_inprogress) {
		if (!uni_engine.startinputtimers)
	  return uni_recog_start_input_timers(uni_speech);
	}

	ast_log(LOG_DEBUG, "(%s) Start recognition\n",uni_speech->name);
	mrcp_message = mrcp_application_message_create(
								uni_speech->session,
								uni_speech->channel,
								RECOGNIZER_RECOGNIZE);
	if(!mrcp_message) {
		ast_log(LOG_WARNING, "(%s) Failed to create MRCP message\n",uni_speech->name);
		return -1;
	}
	
	/* Get/allocate generic header */
	generic_header = mrcp_generic_header_prepare(mrcp_message);
	if(generic_header) {
		apr_hash_index_t *it;
		void *val;
		const void *key;
		const void *binary;
    const char *grammar_name;
		const char *grammar_path;
		const char *content = NULL;
		/* Set generic header fields */
		apt_string_assign(&generic_header->content_type,"text/uri-list",mrcp_message->pool);
		mrcp_generic_header_property_add(mrcp_message,GENERIC_HEADER_CONTENT_TYPE);

		/* Construct and set message body */
		it = apr_hash_first(mrcp_message->pool,uni_speech->active_grammars);
		if(it) {
			apr_hash_this(it,NULL,NULL,&val);
			grammar_name = val;

      binary = apr_hash_get(uni_speech->binary_grammars, grammar_name, APR_HASH_KEY_STRING);
      if (binary)
      {
        grammar_name = binary;
    	  ast_log(LOG_DEBUG, "(%s) Active binary grammar : %s , %s\n", uni_speech->name, val, binary);
  			content = apr_pstrcat(mrcp_message->pool,grammar_name,NULL);
    }
      else
      {
    	  ast_log(LOG_DEBUG, "(%s) Active grammar : %s\n",uni_speech->name, val);
  			content = apr_pstrcat(mrcp_message->pool,"session:", grammar_name,NULL);
      }

			it = apr_hash_next(it);
		}
		for(; it; it = apr_hash_next(it)) {
			apr_hash_this(it,&key,NULL,&val);
			grammar_name = val;

      binary = apr_hash_get(uni_speech->binary_grammars, grammar_name, APR_HASH_KEY_STRING);
      if (binary)
      {
        grammar_name = binary;
    	  ast_log(LOG_DEBUG, "(%s) Active binary grammar : %s , %s\n", uni_speech->name, val, binary);
  			content = apr_pstrcat(mrcp_message->pool,content,"\n",binary,NULL);
      }
      else
      {
    	  ast_log(LOG_DEBUG, "(%s) Active grammar : %s\n",uni_speech->name, val);
	  		content = apr_pstrcat(mrcp_message->pool,content,"\nsession:",grammar_name,NULL);
      }

		}
		if(content) {
			apt_string_set(&mrcp_message->body,content);
		}
	}

	/* Get/allocate recognizer header */
	recog_header = (mrcp_recog_header_t*) mrcp_resource_header_prepare(mrcp_message);
	if(recog_header) {
		/* Set recognizer header fields */
		if(mrcp_message->start_line.version == MRCP_VERSION_2 && uni_engine.cancelifqueue) { // cancelifqueue for Vestec
			recog_header->cancel_if_queue = FALSE;
			mrcp_resource_header_property_add(mrcp_message,RECOGNIZER_HEADER_CANCEL_IF_QUEUE);
		}

		//if (uni_engine.startinputtimers) // startinputtimers for aumtech
		{
		  recog_header->start_input_timers = uni_engine.startinputtimers;
		  mrcp_resource_header_property_add(mrcp_message,RECOGNIZER_HEADER_START_INPUT_TIMERS);
    }
	}

	/* Check the properties set by loadgrammar */
	if(!uni_engine.setparams)
  if(uni_speech->properties) {
	  apt_header_field_t *header_field;
		char value[1000];
		char *unit;

    ast_log(LOG_DEBUG, "Check grammar properties.\n");

	  for(header_field = APR_RING_FIRST(&uni_speech->properties->header_section.ring);
			header_field != APR_RING_SENTINEL(&uni_speech->properties->header_section.ring, apt_header_field_t, link);
				header_field = APR_RING_NEXT(header_field, link)) {

		  /* Dump the content */
      ast_log(LOG_DEBUG, "Property: %s=%s\n", header_field->name.buf, header_field->value.buf);
			if (header_field->value.buf)
			strncpy(value, header_field->value.buf, 1000);
			else
			value[0]=0;

      ast_log(LOG_DEBUG, "MRCP Version : %d\n", mrcp_message->start_line.version);

      if (uni_engine.removeswi && !strncmp(header_field->name.buf, "swi", 3))
			{
        ast_log(LOG_DEBUG, "Remove Nuance property : %s=%s\n", header_field->name.buf, header_field->value);
        apt_header_section_field_remove(&uni_speech->properties->header_section,header_field);
			}
			else
			if(mrcp_message->start_line.version == MRCP_VERSION_1 && (unit = strchr(value, 's')))
			{
        float fvalue;
				float factor = 1000;

				if (unit>value)
				{
				  if (*(unit-1)=='m')
				  {
						unit--;
					  factor = 1;
					}
				}
				else
				factor = 0;

				*unit = 0;

				fvalue = atof(value);
				fvalue = fvalue*factor;

        sprintf(value, "%d", (int)fvalue);

        ast_log(LOG_DEBUG, "Change the value for MRCP V1 : %s=%s\n", header_field->name.buf, value);

				// No previous free, use the pool
        apt_string_assign(&header_field->value, value, mrcp_message->pool);
			}
			else
      if(mrcp_message->start_line.version == MRCP_VERSION_1 && (value[1]=='.' && (value[0]=='0' || value[0]=='1')))
			{
        float fvalue = atof(value);
				fvalue = fvalue*100;

        sprintf(value, "%d", (int)fvalue);

        ast_log(LOG_DEBUG, "Change the value for MRCP V1 : %s=%s\n", header_field->name.buf, value);

				// No previous free, use the pool
        apt_string_assign(&header_field->value, value, mrcp_message->pool);
			}

	  }

  	/* Add properties set by loadgrammar */
#if defined(TRANSPARENT_HEADER_FIELDS_SUPPORT)
		mrcp_header_fields_inherit(&mrcp_message->header,uni_speech->properties,mrcp_message->pool);
#else
		mrcp_message_header_inherit(&mrcp_message->header,uni_speech->properties,mrcp_message->pool);
#endif
  }




	/* Reset last event (if any) */
	uni_speech->mrcp_event = NULL;

	/* Send MRCP request and wait for response */
	if(uni_recog_mrcp_request_send(uni_speech,mrcp_message) != TRUE) {
    ast_log(LOG_WARNING, "(%s) Failed to start recognition\n",uni_speech->name);
		return -1;
	}

	/* Check received response */
	if(!uni_speech->mrcp_response || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "Received failure response\n");
		return -1;
	}
	
	/* Reset media buffer */
	mpf_frame_buffer_restart(uni_speech->media_buffer);
	
	ast_speech_change_state(speech, AST_SPEECH_STATE_READY);
	
	uni_speech->is_inprogress = TRUE;
	return 0;
}

/** \brief Change an engine specific setting */
static int uni_recog_change(struct ast_speech *speech, ast_compat_const char *name, const char *value)
{
	uni_speech_t *uni_speech = speech->data;

	if(uni_speech->is_inprogress) {
		uni_recog_stop(speech);
	}

	ast_log(LOG_NOTICE, "(%s) Change setting name: %s value:%s\n",uni_speech->name,name,value);
	return 0;
}

#if AST_VERSION_AT_LEAST(12,0,0)
/** \brief Get an engine specific attribute */
static int uni_recog_get_settings(struct ast_speech *speech, const char *name, char *buf, size_t len)
{
	uni_speech_t *uni_speech = speech->data;

	ast_log(LOG_NOTICE, "(%s) Get settings name: %s\n",uni_speech->name,name);
	return -1;
}
#endif

/** \brief Change the type of results we want back */
static int uni_recog_change_results_type(struct ast_speech *speech,enum ast_speech_results_type results_type)
{
	uni_speech_t *uni_speech = speech->data;

	if(uni_speech->is_inprogress) {
		uni_recog_stop(speech);
	}

	ast_log(LOG_NOTICE, "(%s) Change result type %d\n",uni_speech->name,results_type);
	return -1;
}


/* Start duplicated code to patch apt_nlsml_doc for Nuance */

/** NLSML instance */
struct nlsml_instance_t
{
	/** Ring entry */
	APR_RING_ENTRY(nlsml_instance_t) link;

	/** Instance element */
	apr_xml_elem *elem;
};

/** Suppress SWI elements (normalize instance) */
APT_DECLARE(apt_bool_t) nlsml_instance_swi_suppress2(nlsml_instance_t *instance)
{
	apr_xml_elem *child_elem;
	apr_xml_elem *prev_elem = NULL;
	apr_xml_elem *swi_literal = NULL;
	apr_xml_elem *swi_meaning = NULL;
	apr_xml_elem *swi_grammarname = NULL;
	apt_bool_t remove;
	if(!instance->elem)
		return FALSE;

	for(child_elem = instance->elem->first_child; child_elem; child_elem = child_elem->next) {
		remove = FALSE;
		if(strcasecmp(child_elem->name,"SWI_literal") == 0) {
			swi_literal = child_elem;
			remove = TRUE;
		}
		else if(strcasecmp(child_elem->name,"SWI_meaning") == 0) {
			swi_meaning = child_elem;
			remove = TRUE;
		}
		else if(strcasecmp(child_elem->name,"SWI_grammarName") == 0) {
			swi_grammarname = child_elem;
			remove = TRUE;
		}

		if(remove == TRUE) {
    	ast_log(LOG_NOTICE, "nlsml_instance_swi_suppress2: remove %s\n", child_elem->name);

			if(child_elem == instance->elem->first_child) {
				instance->elem->first_child = child_elem->next;
			}
			else if(prev_elem) {
				prev_elem->next = child_elem->next;
			}
		}

		prev_elem = child_elem;
	}

	if(APR_XML_ELEM_IS_EMPTY(instance->elem) && swi_literal) {
 		ast_log(LOG_NOTICE, "nlsml_instance_swi_suppress2: Instance empty, get the SWI_literal CDATA\n");
		instance->elem->first_cdata = swi_literal->first_cdata;
	}

	return TRUE;
}

/* End of duplication */

/** \brief Build ast_speech_result based on the NLSML result */
static struct ast_speech_result* uni_recog_speech_result_build(uni_speech_t *uni_speech, const apt_str_t *nlsml_result, mrcp_version_e mrcp_version)
{
	float confidence;
	const char *grammar;
	const char *text;
	struct ast_speech_result *speech_result;
	struct ast_speech_result *first_speech_result;
	nlsml_interpretation_t *interpretation;
	nlsml_instance_t *instance;
	nlsml_input_t *input;
	int interpretation_count;
	int instance_count;
	char filename[100]="/tmp/unimrcp.xml";
  FILE *file;

	apr_pool_t *pool = mrcp_application_session_pool_get(uni_speech->session);

	if (uni_engine.returnnlsml)
	{
		sprintf(filename, "/tmp/%s.xml", uni_speech->name);

    file = fopen(filename, "wb");
    if (file != NULL)
		{
      fwrite(nlsml_result->buf, 1, nlsml_result->length, file);

			fclose(file);
		}
	}

	nlsml_result_t *result = nlsml_result_parse(nlsml_result->buf, nlsml_result->length, pool);
	if(!result) {
		ast_log(LOG_WARNING, "(%s) Failed to parse NLSML result: %s\n",uni_speech->name,nlsml_result->buf);
		return NULL;
	}

	if (!uni_engine.returnnlsml)
	{
	  // Nuance needs to execute our function first to remove SWI_grammarName
	  interpretation = nlsml_first_interpretation_get(result);
	  while(interpretation) {
		  input = nlsml_interpretation_input_get(interpretation);
		  instance = nlsml_interpretation_first_instance_get(interpretation);
		  while(instance) {
			  nlsml_instance_swi_suppress2(instance);
			  instance = nlsml_interpretation_next_instance_get(interpretation, instance);
		  }
      interpretation = nlsml_next_interpretation_get(result, interpretation);
	  }
	}

#if 1 /* enable/disable debug output of parsed results */
	nlsml_result_trace(result, pool);
#endif

	first_speech_result = NULL;
#if AST_VERSION_AT_LEAST(1,6,0)
	AST_LIST_HEAD_NOLOCK(, ast_speech_result) speech_results;
	AST_LIST_HEAD_INIT_NOLOCK(&speech_results);
#else
	struct ast_speech_result *last_speech_result = NULL;
#endif

	interpretation_count = 0;
	interpretation = nlsml_first_interpretation_get(result);
	while(interpretation) {
		input = nlsml_interpretation_input_get(interpretation);
		if(!input) {
			ast_log(LOG_WARNING, "(%s) Failed to get NLSML input.\n",uni_speech->name);
			continue;
		}

		instance_count = 0;
		instance = nlsml_interpretation_first_instance_get(interpretation);
		if(!instance) {
			ast_log(LOG_DEBUG, "(%s) Failed to get NLSML instance, using input.\n",uni_speech->name);
			//continue;
		}

  	/* Only for future debug
	  {
	  apr_xml_elem *child_elem;
	  const apr_xml_attr *xml_attr;
	  for(child_elem = interpret->first_child; child_elem; child_elem = child_elem->next) {
		  ast_log(LOG_WARNING, "PARSING Child interpreter '%s'\n", child_elem->name);
	  }

	  for(xml_attr = interpret->attr; xml_attr; xml_attr = xml_attr->next) {
		ast_log(LOG_WARNING, "PARSING Attr interpreter '%s'\n", xml_attr->name);
	  }
	  }
	  */


		confidence = nlsml_interpretation_confidence_get(interpretation);
		grammar = nlsml_interpretation_grammar_get(interpretation);

		if(grammar) {
			const char session_token[] = "session:";
			char *str = strstr(grammar,session_token);
			if(str) {
				grammar = str + sizeof(session_token) - 1;
			}
		}

		do {
			// Nuance needs to remove SWI_grammarName too
			if (instance)
			{
			  nlsml_instance_swi_suppress2(instance);
			  text = nlsml_instance_content_generate(instance, pool);

				if (text)
        ast_log(LOG_DEBUG, "(%s) text=%s, using instance.\n",uni_speech->name, text);
			}
			else
			text = NULL;

			// Nuance Instance can be empty if without SWI
			if ((!text) || !(*text))
			{
			  text = nlsml_input_content_generate(input,pool);
				if (text)
        ast_log(LOG_DEBUG, "(%s) text=%s, using input.\n",uni_speech->name, text);
			}

			speech_result = ast_calloc(sizeof(struct ast_speech_result), 1);


			if (uni_engine.returnnlsml)
			{
				speech_result->text = strdup(filename);
			}
			else
			if(text)
				speech_result->text = strdup(text);



			speech_result->score = confidence * 100;
			if(grammar)
				speech_result->grammar = strdup(grammar);
			speech_result->nbest_num = interpretation_count;
			if(!first_speech_result)
				first_speech_result = speech_result;
#if AST_VERSION_AT_LEAST(1,6,0)
			AST_LIST_INSERT_TAIL(&speech_results, speech_result, list);
#else
			speech_result->next = last_speech_result;
			last_speech_result = speech_result;
#endif
			ast_log(LOG_DEBUG, "(%s) Speech result[%d/%d]: %s, score: %d, grammar: %s\n",
					uni_speech->name,
					interpretation_count,
					instance_count,
					speech_result->text,
					speech_result->score,
					speech_result->grammar);

			instance_count++;

			if (uni_engine.returnnlsml)
			instance=NULL;
			else
      if (instance)
			instance = nlsml_interpretation_next_instance_get(interpretation, instance);
		}
		while(instance);

		interpretation_count++;

		if (uni_engine.returnnlsml)
    interpretation = NULL;
		else
		interpretation = nlsml_next_interpretation_get(result, interpretation);
	}

	return first_speech_result;
}

/** \brief Try to get result */
struct ast_speech_result* uni_recog_get(struct ast_speech *speech)
{
	struct ast_speech_result *result;
	mrcp_recog_header_t *recog_header;

	uni_speech_t *uni_speech = speech->data;

	if (uni_speech->properties)
	{
    mrcp_message_header_destroy(uni_speech->properties);
    uni_speech->properties = NULL;
	}

	if(uni_speech->is_inprogress) {
		uni_recog_stop(speech);
    ast_log(LOG_DEBUG, "RECOGNITION stopped\n");
		return NULL;
	}

	ast_log(LOG_DEBUG, "Get result '%s'\n",uni_speech->name);
	if(!uni_speech->mrcp_event) {
		ast_log(LOG_WARNING, "(%s) No RECOGNITION-COMPLETE message received\n",uni_speech->name);
		return NULL;
	}

	/* Get recognizer header */
	recog_header = mrcp_resource_header_get(uni_speech->mrcp_event);
	if(!recog_header || mrcp_resource_header_property_check(uni_speech->mrcp_event,RECOGNIZER_HEADER_COMPLETION_CAUSE) != TRUE) {
		ast_log(LOG_WARNING, "(%s) Missing completion cause in RECOGNITION-COMPLETE message\n",uni_speech->name);
		return NULL;
	}

	if(speech->results) {
		ast_speech_results_free(speech->results);
    speech->results = NULL;
	}

	ast_log(LOG_DEBUG, "(%s) Get result completion cause: %03d reason: %s\n",
			uni_speech->name,
			recog_header->completion_cause,
			recog_header->completion_reason.buf ? recog_header->completion_reason.buf : "none");

	if(recog_header->completion_cause != RECOGNIZER_COMPLETION_CAUSE_SUCCESS) {
		result = NULL;

		if (recog_header->completion_cause == 1) // nomatch
		{
	    ast_log(LOG_DEBUG, "(%s) Set empty result for nomatch\n", uni_speech->name);

      struct ast_speech_result *speech_result;
			speech_result	= ast_calloc(sizeof(struct ast_speech_result), 1);

#if AST_VERSION_AT_LEAST(1,6,0)
	AST_LIST_HEAD_NOLOCK(, ast_speech_result) speech_results;
	AST_LIST_HEAD_INIT_NOLOCK(&speech_results);
#else
#endif

			speech_result->text = strdup("");
			speech_result->score = 0;

			speech_result->grammar = NULL;
			speech_result->nbest_num = 0;
#if AST_VERSION_AT_LEAST(1,6,0)
			AST_LIST_INSERT_TAIL(&speech_results, speech_result, list);
#else
			speech_result->next = NULL;
#endif

			result = speech_result;
    }
		else
		if (recog_header->completion_cause == 2) // noinput
		{
	    ast_log(LOG_DEBUG, "(%s) Set null result for noinput\n", uni_speech->name);
		}
		else
		{
    		ast_log(LOG_WARNING, "(%s) Recognition completed abnormally cause: %03d reason: %s\n",
				uni_speech->name,
				recog_header->completion_cause,
				recog_header->completion_reason.buf ? recog_header->completion_reason.buf : "none");
        return NULL;
		}

		return result;
	}

	result = uni_recog_speech_result_build(
					uni_speech,
					&uni_speech->mrcp_event->body,
					uni_speech->mrcp_event->start_line.version);
	if(result)
		ast_set_flag(speech,AST_SPEECH_HAVE_RESULTS);

	return result;
}


/*! \brief Signal session management response */
static apt_bool_t uni_recog_sm_response_signal(uni_speech_t *uni_speech, mrcp_sig_command_e request, mrcp_sig_status_code_e status)
{
	if (!uni_speech->mutex)
	return FALSE;

	apr_thread_mutex_lock(uni_speech->mutex);

	if(uni_speech->sm_request == request) {
		uni_speech->sm_response = status;
		apr_thread_cond_signal(uni_speech->wait_object);
	}
	else {
		ast_log(LOG_WARNING, "(%s) Received unexpected response %d, while waiting for %d\n",
					uni_speech->name,
					request, 
					uni_speech->sm_request);
	}

	apr_thread_mutex_unlock(uni_speech->mutex);
	return TRUE;
}

/*! \brief Signal MRCP response */
static apt_bool_t uni_recog_mrcp_response_signal(uni_speech_t *uni_speech, mrcp_message_t *message)
{
	if (!uni_speech->mutex)
	return FALSE;

	apr_thread_mutex_lock(uni_speech->mutex);

	if(uni_speech->mrcp_request) {
		uni_speech->mrcp_response = message;
		apr_thread_cond_signal(uni_speech->wait_object);
	}
	else {
		ast_log(LOG_WARNING, "(%s) Received unexpected MRCP response\n",uni_speech->name);
	}
 
	apr_thread_mutex_unlock(uni_speech->mutex);
	return TRUE;
}

/** \brief Received session update response */
static apt_bool_t on_session_update(mrcp_application_t *application, mrcp_session_t *session, mrcp_sig_status_code_e status)
{
	struct ast_speech *speech = mrcp_application_session_object_get(session);
	uni_speech_t *uni_speech = speech->data;

	ast_log(LOG_DEBUG, "(%s) Session updated status: %d\n",uni_speech->name, status);
	return uni_recog_sm_response_signal(uni_speech,MRCP_SIG_COMMAND_SESSION_UPDATE,status);
}

/** \brief Received session termination response */
static apt_bool_t on_session_terminate(mrcp_application_t *application, mrcp_session_t *session, mrcp_sig_status_code_e status)
{
	struct ast_speech *speech = mrcp_application_session_object_get(session);

	{
    if(uni_engine.mutex) apr_thread_mutex_lock(uni_engine.mutex);
    uni_engine.current_speech_sessions--;

		ast_log(LOG_DEBUG, "Speech sessions :%d/%d\n",
		 uni_engine.current_speech_sessions,
		 uni_engine.max_speech_sessions);

	  if(uni_engine.mutex) apr_thread_mutex_unlock(uni_engine.mutex);

	  if (!speech)
		{
    	ast_log(LOG_DEBUG, "(%s) Session terminated status: %d\n","unref", status);

    	ast_log(LOG_DEBUG, "Destroy application session\n");
		  mrcp_application_session_destroy(session);
	    return FALSE;
		}
	}

	uni_speech_t *uni_speech = speech->data;

	if (!uni_speech)
	return FALSE;

  uni_speech->speech_base = NULL;

  if (uni_speech->dtmf_generator != NULL) {
		ast_log(LOG_DEBUG, "(%s) DTMF generator destroyed\n", uni_speech->name);
		mpf_dtmf_generator_destroy(uni_speech->dtmf_generator);
		uni_speech->dtmf_generator = NULL;
	}

	ast_log(LOG_DEBUG, "(%s) Session terminated status: %d\n",uni_speech->name, status);
	if (uni_recog_sm_response_signal(uni_speech,MRCP_SIG_COMMAND_SESSION_TERMINATE,status))
	{
		return TRUE;
	}
	else
	{
  	//ast_log(LOG_DEBUG, "(%s) Destroy application session : %d\n",uni_speech->name);
		//mrcp_application_session_destroy(session);

		return FALSE;
	}
}

/** \brief Received channel add response */
static apt_bool_t on_channel_add(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_sig_status_code_e status)
{
	uni_speech_t *uni_speech = mrcp_application_channel_object_get(channel);
  apr_pool_t *pool = mrcp_application_session_pool_get(uni_speech->session);

  //if (0)
  if (uni_speech->stream != NULL)
  if (uni_speech->dtmf_generator == NULL)
  {
				uni_speech->dtmf_generator = mpf_dtmf_generator_create(uni_speech->stream, pool);

				if (uni_speech->dtmf_generator != NULL)
					ast_log(LOG_DEBUG, "(%s) DTMF generator created\n", uni_speech->name);
				else
					ast_log(LOG_WARNING, "(%s) Unable to create DTMF generator\n", uni_speech->name);
	}

	ast_log(LOG_DEBUG, "(%s) Channel added status: %d\n",uni_speech->name, status);
	return uni_recog_sm_response_signal(uni_speech,MRCP_SIG_COMMAND_CHANNEL_ADD,status);
}

/** \brief Received channel remove response */
static apt_bool_t on_channel_remove(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_sig_status_code_e status)
{
	uni_speech_t *uni_speech = mrcp_application_channel_object_get(channel);

	ast_log(LOG_DEBUG, "(%s) Channel removed status: %d\n",uni_speech->name, status);
	return uni_recog_sm_response_signal(uni_speech,MRCP_SIG_COMMAND_CHANNEL_REMOVE,status);
}

/** \brief Received MRCP message */
static apt_bool_t on_message_receive(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel, mrcp_message_t *message)
{
	uni_speech_t *uni_speech = mrcp_application_channel_object_get(channel);

	if (!uni_speech->speech_base)
	return FALSE;

	if(message->start_line.message_type == MRCP_MESSAGE_TYPE_RESPONSE) {
		ast_log(LOG_DEBUG, "(%s) Received MRCP response method-id: %d status-code: %d req-state: %d\n",
				uni_speech->name,
				(int)message->start_line.method_id,
				message->start_line.status_code,
				(int)message->start_line.request_state);
	
    if(message->start_line.method_id == RECOGNIZER_STOP) {  // Correction for Aumtech
	    ast_speech_change_state(
		    uni_speech->speech_base,AST_SPEECH_STATE_DONE);
    }
		return uni_recog_mrcp_response_signal(uni_speech,message);
	}

	if(message->start_line.message_type == MRCP_MESSAGE_TYPE_EVENT) {
		if(message->start_line.method_id == RECOGNIZER_RECOGNITION_COMPLETE) {
			ast_log(LOG_DEBUG, "(%s) Recognition complete req-state: %d\n",
					uni_speech->name,
					(int)message->start_line.request_state);
			uni_speech->is_inprogress = FALSE;
			if (uni_speech->speech_base->state != AST_SPEECH_STATE_NOT_READY) {
				uni_speech->mrcp_event = message;
				ast_speech_change_state(uni_speech->speech_base,AST_SPEECH_STATE_DONE);
			}
			else {
			        ast_log(LOG_DEBUG, "(%s) Unexpected RECOGNITION-COMPLETE event\n",uni_speech->name);
			        
				uni_speech->mrcp_event = NULL;
				ast_speech_change_state(uni_speech->speech_base,AST_SPEECH_STATE_NOT_READY);
				
			}
		}
		else if(message->start_line.method_id == RECOGNIZER_START_OF_INPUT) {
			ast_log(LOG_DEBUG, "(%s) Start of input\n",uni_speech->name);
			ast_set_flag(uni_speech->speech_base, AST_SPEECH_QUIET | AST_SPEECH_SPOKE);
		}
		else {
			ast_log(LOG_DEBUG, "(%s) Received unhandled MRCP event id: %d req-state: %d\n",
					uni_speech->name,
					(int)message->start_line.method_id,
					(int)message->start_line.request_state);
		}
	}

	return TRUE;
}

/** \brief Received unexpected session/channel termination event */
static apt_bool_t on_terminate_event(mrcp_application_t *application, mrcp_session_t *session, mrcp_channel_t *channel)
{
	uni_speech_t *uni_speech = mrcp_application_channel_object_get(channel);
	if (uni_speech)
	ast_log(LOG_WARNING, "(%s) Received unexpected session termination event\n",uni_speech->name);
	else
	ast_log(LOG_WARNING, "(?) Received unexpected session termination event\n");
	return TRUE;
}

/** \brief Received response to resource discovery request */
static apt_bool_t on_resource_discover(mrcp_application_t *application, mrcp_session_t *session, mrcp_session_descriptor_t *descriptor, mrcp_sig_status_code_e status)
{
	return TRUE;
}

static const mrcp_app_message_dispatcher_t uni_dispatcher = {
	on_session_update,
	on_session_terminate,
	on_channel_add,
	on_channel_remove,
	on_message_receive,
	on_terminate_event,
	on_resource_discover
};

/** \brief UniMRCP message handler */
static apt_bool_t uni_message_handler(const mrcp_app_message_t *app_message)
{
	return mrcp_application_message_dispatch(&uni_dispatcher,app_message);
}

/** \brief UniMRCP callback requesting stream to be opened. */
static apt_bool_t uni_recog_stream_open(mpf_audio_stream_t* stream, mpf_codec_t *codec)
{
	uni_speech_t* uni_speech;

	if (stream != NULL)
		uni_speech = (uni_speech_t*)stream->obj;
	else
		uni_speech = NULL;

	uni_speech->stream = stream;

	if ((uni_speech == NULL) || (stream == NULL))
		ast_log(LOG_ERROR, "(unknown) channel error opening stream!\n");

	return TRUE;
}

/** \brief Process MPF frame */
static apt_bool_t uni_recog_stream_read(mpf_audio_stream_t *stream, mpf_frame_t *frame)
{
	uni_speech_t *uni_speech = stream->obj;

	if (uni_speech->dtmf_generator != NULL) {
			if (mpf_dtmf_generator_sending(uni_speech->dtmf_generator)) {
				ast_log(LOG_DEBUG, "(%s) DTMF frame written\n", uni_speech->name);
				mpf_dtmf_generator_put_frame(uni_speech->dtmf_generator, frame);
				return TRUE;
			}
	}

	if(uni_speech->media_buffer) {
		mpf_frame_buffer_read(uni_speech->media_buffer,frame);
#if 0
		ast_log(LOG_DEBUG, "(%s) Read audio type: %d len: %d\n",
			uni_speech->name,
			frame->type,
			frame->codec_frame.size);
#endif
	}
	return TRUE;
}

/** \brief Methods of audio stream */
static const mpf_audio_stream_vtable_t audio_stream_vtable = {
	NULL,
	uni_recog_stream_open,
	NULL,
	uni_recog_stream_read,
	NULL,
	NULL,
	NULL
};

/** \brief Create recognition channel */
static apt_bool_t uni_recog_channel_create(uni_speech_t *uni_speech, ast_format_compat *format)
{
	mrcp_channel_t *channel;
	mpf_termination_t *termination;
	mpf_stream_capabilities_t *capabilities;
	apr_pool_t *pool = mrcp_application_session_pool_get(uni_speech->session);

	/* Create source stream capabilities */
	capabilities = mpf_source_stream_capabilities_create(pool);
	/* Add codec capabilities (Linear PCM) */
	mpf_codec_capabilities_add(
			&capabilities->codecs,
			MPF_SAMPLE_RATE_8000,
			"LPCM");

	/* Create media termination */
	termination = mrcp_application_audio_termination_create(
			uni_speech->session,      /* session, termination belongs to */
			&audio_stream_vtable,     /* virtual methods table of audio stream */
			capabilities,             /* stream capabilities */
			uni_speech);              /* object to associate */

	/* Create MRCP channel */
	channel = mrcp_application_channel_create(
			uni_speech->session,      /* session, channel belongs to */
			MRCP_RECOGNIZER_RESOURCE, /* MRCP resource identifier */
			termination,              /* media termination, used to terminate audio stream */
			NULL,                     /* RTP descriptor, used to create RTP termination (NULL by default) */
			uni_speech);              /* object to associate */

	if(!channel) {
		return FALSE;
	}
	uni_speech->channel = channel;
	return TRUE;
}

/** \brief Set properties */
static apt_bool_t uni_recog_properties_set(uni_speech_t *uni_speech)
{
	apr_pool_t *pool = mrcp_application_session_pool_get(uni_speech->session);
	mrcp_message_t *mrcp_message;
	mrcp_message_header_t *properties;

  char vendorparameters[1000];

  vendorparameters[0]=0;

	ast_log(LOG_DEBUG, "(%s) Set properties\n",uni_speech->name);
	mrcp_message = mrcp_application_message_create(
								uni_speech->session,
								uni_speech->channel,
								RECOGNIZER_SET_PARAMS);
	if(!mrcp_message) {
		ast_log(LOG_WARNING, "(%s) Failed to create MRCP message\n",uni_speech->name);
		return FALSE;
	}

	/* Inherit properties loaded from config */
	if(mrcp_message->start_line.version == MRCP_VERSION_2) {
		properties = uni_engine.v2_properties;
	}
	else {
		properties = uni_engine.v1_properties;
	}

	/* Check the properties set by loadgrammar */
  if(uni_speech->properties) {
	  apt_header_field_t *header_field;
		char value[1000];
		char *unit;

    vendorparameters[0]=0;
    properties = NULL;

    ast_log(LOG_DEBUG, "Check grammar properties.\n");

    ast_log(LOG_DEBUG, "MRCP Version : %d\n", mrcp_message->start_line.version);

	  for(header_field = APR_RING_FIRST(&uni_speech->properties->header_section.ring);
			header_field != APR_RING_SENTINEL(&uni_speech->properties->header_section.ring, apt_header_field_t, link);
				header_field = APR_RING_NEXT(header_field, link)) {

		  /* Dump the content */
      ast_log(LOG_DEBUG, "Property: %s=%s\n", header_field->name.buf, header_field->value.buf);
			if (header_field->value.buf)
			strncpy(value, header_field->value.buf, 1000);
			else
			value[0]=0;

      if (uni_engine.removeswi && !strncmp(header_field->name.buf, "swi", 3))
			{
        ast_log(LOG_DEBUG, "Remove Nuance property : %s=%s\n", header_field->name.buf, header_field->value);

				if (vendorparameters[0])
				strcat(vendorparameters, ";");

				if (!apt_string_is_empty(&header_field->value))
				sprintf(value, "%s=\"%s\"", header_field->name.buf, header_field->value);
				else
				sprintf(value, "%s=\"\"", header_field->name.buf);

				if (uni_engine.vendorspecificparameters)
				strcat(vendorparameters, value);

        apt_header_section_field_remove(&uni_speech->properties->header_section,header_field);
			}
			else
			if(mrcp_message->start_line.version == MRCP_VERSION_1 && (unit = strchr(value, 's')))
			{
        float fvalue;
				float factor = 1000;

				if (unit>value)
				{
				  if (*(unit-1)=='m')
				  {
						unit--;
					  factor = 1;
					}
				}
				else
				factor = 0;

				*unit = 0;

				fvalue = atof(value);
				fvalue = fvalue*factor;

        sprintf(value, "%d", (int)fvalue);

        ast_log(LOG_DEBUG, "Change the value for MRCP V1 : %s=%s\n", header_field->name.buf, value);

				// No previous free, use the pool
        apt_string_assign(&header_field->value, value, mrcp_message->pool);
			}
			else
      if(mrcp_message->start_line.version == MRCP_VERSION_1 && (value[1]=='.' && (value[0]=='0' || value[0]=='1')))
			{
        float fvalue = atof(value);
				fvalue = fvalue*100;

        sprintf(value, "%d", (int)fvalue);

        ast_log(LOG_DEBUG, "Change the value for MRCP V1 : %s=%s\n", header_field->name.buf, value);

				// No previous free, use the pool
        apt_string_assign(&header_field->value, value, mrcp_message->pool);
			}

	  }
	}

	if(properties) {
#if defined(TRANSPARENT_HEADER_FIELDS_SUPPORT)
		mrcp_header_fields_inherit(&mrcp_message->header,properties,mrcp_message->pool);
#else
		mrcp_message_header_inherit(&mrcp_message->header,properties,mrcp_message->pool);
#endif
	}

  properties = uni_speech->properties;
  if (properties) {
#if defined(TRANSPARENT_HEADER_FIELDS_SUPPORT)
		mrcp_header_fields_inherit(&mrcp_message->header,properties,mrcp_message->pool);
#else
		mrcp_message_header_inherit(&mrcp_message->header,properties,mrcp_message->pool);
#endif
	}

  /* Add properties set by loadgrammar (Vendor-Specific-Parameters) */
	if (vendorparameters[0])
	{
  	apt_header_field_t *header_field;

    ast_log(LOG_DEBUG, "Set Vendor-Specific-Parameters : %s\n", vendorparameters);

  	header_field = apt_header_field_create_c("Vendor-Specific-Parameters",vendorparameters, pool);
		apt_header_section_field_add(&mrcp_message->header.header_section,header_field);
 	}

	/* Send MRCP request and wait for response */
	if(uni_recog_mrcp_request_send(uni_speech,mrcp_message) != TRUE) {
    ast_log(LOG_WARNING, "(%s) Failed to set properties\n",uni_speech->name);
		return FALSE;
	}

	/* Check received response */
	if(!uni_speech->mrcp_response || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "Received failure response\n");
		return FALSE;
	}
	return TRUE;
}


/** \brief Start Input Timers */
static apt_bool_t uni_recog_start_input_timers(uni_speech_t *uni_speech)
{
	mrcp_message_t *mrcp_message;
	mrcp_message_header_t *properties;


	ast_log(LOG_DEBUG, "(%s) Start Input Timers\n",uni_speech->name);
	mrcp_message = mrcp_application_message_create(
								uni_speech->session,
								uni_speech->channel,
								RECOGNIZER_START_INPUT_TIMERS);
	if(!mrcp_message) {
		ast_log(LOG_WARNING, "(%s) Failed to create MRCP message\n",uni_speech->name);
		return FALSE;
	}

	/* Inherit properties loaded from config */
	if(mrcp_message->start_line.version == MRCP_VERSION_2) {
		properties = uni_engine.v2_properties;
	}
	else {
		properties = uni_engine.v1_properties;
	}

	/* Send MRCP request and wait for response */
	if(uni_recog_mrcp_request_send(uni_speech,mrcp_message) != TRUE) {
    ast_log(LOG_WARNING, "(%s) Failed to set properties\n",uni_speech->name);
		return FALSE;
	}

	/* Check received response */
	if(!uni_speech->mrcp_response || uni_speech->mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS) {
		ast_log(LOG_WARNING, "Received failure response\n");
		return FALSE;
	}
	return TRUE;
}

/** \brief Preload grammar */
static apt_bool_t uni_recog_grammars_preload(uni_speech_t *uni_speech)
{
	apr_table_t *grammars = uni_engine.grammars;
	if(grammars && uni_speech->session) {
		int i;
		char *grammar_name;
		char *grammar_path;
		apr_pool_t *pool = mrcp_application_session_pool_get(uni_speech->session);
		const apr_array_header_t *header = apr_table_elts(grammars);
		apr_table_entry_t *entry = (apr_table_entry_t *) header->elts;
		for(i=0; i<header->nelts; i++) {
			grammar_name = apr_pstrdup(pool,entry[i].key);
			grammar_path = apr_pstrdup(pool,entry[i].val);
			uni_recog_load_grammar(uni_speech->speech_base,grammar_name,grammar_path);
		}
	}
	return TRUE;
}

/** \brief Send session management request to client stack and wait for async response */
static apt_bool_t uni_recog_sm_request_send(uni_speech_t *uni_speech, mrcp_sig_command_e sm_request)
{
	apt_bool_t res = FALSE;
	ast_log(LOG_DEBUG, "(%s) Send session request type: %d\n",uni_speech->name,sm_request);
	apr_thread_mutex_lock(uni_speech->mutex);
	uni_speech->is_sm_request = TRUE;
	uni_speech->sm_request = sm_request;
	switch(sm_request) {
		case MRCP_SIG_COMMAND_SESSION_UPDATE:
			res = mrcp_application_session_update(uni_speech->session);
			break;
		case MRCP_SIG_COMMAND_SESSION_TERMINATE:
			res = mrcp_application_session_terminate(uni_speech->session);
			break;
		case MRCP_SIG_COMMAND_CHANNEL_ADD:
			res = mrcp_application_channel_add(uni_speech->session,uni_speech->channel);
			break;
		case MRCP_SIG_COMMAND_CHANNEL_REMOVE:
			res = mrcp_application_channel_remove(uni_speech->session,uni_speech->channel);
			break;
		case MRCP_SIG_COMMAND_RESOURCE_DISCOVER:
			res = mrcp_application_resource_discover(uni_speech->session);
			break;
		default:
			break;
	}

	if(res == TRUE) {
		/* Wait for session response */
		ast_log(LOG_DEBUG, "(%s) Wait for session response type: %d\n",uni_speech->name,sm_request);
		if(apr_thread_cond_timedwait(uni_speech->wait_object,uni_speech->mutex,MRCP_APP_REQUEST_TIMEOUT) != APR_SUCCESS) {
			ast_log(LOG_ERROR, "(%s) Failed to get session response: request timed out\n",uni_speech->name);
			uni_speech->sm_response = MRCP_SIG_STATUS_CODE_FAILURE;
		}
		ast_log(LOG_DEBUG, "(%s) Process session response type: %d status: %d\n",uni_speech->name,sm_request,uni_speech->sm_response);
	}

	uni_speech->is_sm_request = FALSE;
	apr_thread_mutex_unlock(uni_speech->mutex);
	return res;
}

/** \brief Send MRCP request to client stack and wait for async response */
static apt_bool_t uni_recog_mrcp_request_send(uni_speech_t *uni_speech, mrcp_message_t *message)
{
	apt_bool_t res = FALSE;
	apr_thread_mutex_lock(uni_speech->mutex);
	uni_speech->mrcp_request = message;

	/* Send MRCP request */
	ast_log(LOG_DEBUG, "(%s) Send MRCP request method-id: %d\n",uni_speech->name,(int)message->start_line.method_id);
	res = mrcp_application_message_send(uni_speech->session,uni_speech->channel,message);
	if(res == TRUE) {
		/* Wait for MRCP response */
		ast_log(LOG_DEBUG, "(%s) Wait for MRCP response\n",uni_speech->name);
		if(apr_thread_cond_timedwait(uni_speech->wait_object,uni_speech->mutex,MRCP_APP_REQUEST_TIMEOUT) != APR_SUCCESS) {
			ast_log(LOG_ERROR, "(%s) Failed to get MRCP response: request timed out\n",uni_speech->name);
			uni_speech->mrcp_response = NULL;
		}

		/* Wake up and check received response */
		if(uni_speech->mrcp_response) {
			mrcp_message_t *mrcp_response = uni_speech->mrcp_response;
			ast_log(LOG_DEBUG, "(%s) Process MRCP response method-id: %d status-code: %d\n",
					uni_speech->name, 
					(int)mrcp_response->start_line.method_id,
					mrcp_response->start_line.status_code);
			
			if(mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS && 
				mrcp_response->start_line.status_code != MRCP_STATUS_CODE_SUCCESS_WITH_IGNORE) {
				ast_log(LOG_WARNING, "(%s) MRCP request failed method-id: %d status-code: %d\n",
						uni_speech->name,
						(int)mrcp_response->start_line.method_id,
						mrcp_response->start_line.status_code);
				res = FALSE;
			}
		}
		else {
			ast_log(LOG_ERROR, "(%s) No MRCP response available\n",uni_speech->name);
			res = FALSE;
		}
	}
	else {
		ast_log(LOG_WARNING, "(%s) Failed to send MRCP request\n",uni_speech->name);
	}
	uni_speech->mrcp_request = NULL;
	apr_thread_mutex_unlock(uni_speech->mutex);
	return res;
}

/** \brief Speech engine declaration */
static struct ast_speech_engine ast_engine = {
	UNI_ENGINE_NAME,
	uni_recog_create,
	uni_recog_destroy,
	uni_recog_load_grammar,
	uni_recog_unload_grammar,
	uni_recog_activate_grammar,
	uni_recog_deactivate_grammar,
	uni_recog_write,
	uni_recog_dtmf,
	uni_recog_start,
	uni_recog_change,
#if AST_VERSION_AT_LEAST(12,0,0)
	uni_recog_get_settings,
#endif
	uni_recog_change_results_type,
	uni_recog_get
};

/** \brief Load properties from config */
static mrcp_message_header_t* uni_engine_properties_load(struct ast_config *cfg, const char *category, mrcp_version_e version, apr_pool_t *pool)
{
	struct ast_variable *var;
	mrcp_message_header_t *properties = NULL;

#if defined(TRANSPARENT_HEADER_FIELDS_SUPPORT)
	apt_header_field_t *header_field;
	properties = mrcp_message_header_create(
		mrcp_generic_header_vtable_get(version),
		mrcp_recog_header_vtable_get(version),
		pool);
	for(var = ast_variable_browse(cfg, category); var; var = var->next) {
		ast_log(LOG_DEBUG, "%s.%s=%s\n", category, var->name, var->value);
		header_field = apt_header_field_create_c(var->name,var->value,pool);
		if(header_field) {
			if(mrcp_header_field_add(properties,header_field,pool) == FALSE) {
				ast_log(LOG_WARNING, "Unknown MRCP header %s.%s=%s\n", category, var->name, var->value);
			}
		}
	}
#else
	apt_pair_t pair;
	properties = apr_palloc(pool,sizeof(mrcp_message_header_t));
	mrcp_message_header_init(properties);
	properties->generic_header_accessor.vtable = mrcp_generic_header_vtable_get(version);
	properties->resource_header_accessor.vtable = mrcp_recog_header_vtable_get(version);
	mrcp_header_allocate(&properties->generic_header_accessor,pool);
	mrcp_header_allocate(&properties->resource_header_accessor,pool);
	for(var = ast_variable_browse(cfg, category); var; var = var->next) {
		ast_log(LOG_DEBUG, "%s.%s=%s\n", category, var->name, var->value);
		apt_string_set(&pair.name,var->name);
		apt_string_set(&pair.value,var->value);
		if(mrcp_header_parse(&properties->resource_header_accessor,&pair,pool) != TRUE) {
			if(mrcp_header_parse(&properties->generic_header_accessor,&pair,pool) != TRUE) {
				ast_log(LOG_WARNING, "Unknown MRCP header %s.%s=%s\n", category, var->name, var->value);
			}
		}
	}
#endif
	return properties;
}

/** \brief Load grammars from config */
static apr_table_t* uni_engine_grammars_load(struct ast_config *cfg, const char *category, apr_pool_t *pool)
{
	struct ast_variable *var;
	apr_table_t *grammars = apr_table_make(pool,0);
	for(var = ast_variable_browse(cfg, category); var; var = var->next) {
		ast_log(LOG_DEBUG, "%s.%s=%s\n", category, var->name, var->value);
		apr_table_set(grammars,var->name,var->value);
	}
	return grammars;
}

/** \brief Load UniMRCP engine configuration (/etc/asterisk/res_speech_unimrcp.conf)*/
static apt_bool_t uni_engine_config_load(apr_pool_t *pool)
{
	const char *value = NULL;
#if AST_VERSION_AT_LEAST(1,6,0)
	struct ast_flags config_flags = { 0 };
	struct ast_config *cfg = ast_config_load(UNI_ENGINE_CONFIG, config_flags);
#else
	struct ast_config *cfg = ast_config_load(UNI_ENGINE_CONFIG);
#endif

#if AST_VERSION_AT_LEAST(1,6,0)
	if (!cfg)
	cfg = ast_config_load("unimrcp.conf", config_flags);
	if (!cfg)
	cfg = ast_config_load("res_speech_unimrcp.conf", config_flags);
	if (!cfg)
	cfg = ast_config_load(UNI_ENGINE_CONFIG, config_flags);
#else
	if (!cfg)
	cfg = ast_config_load("unimrcp.conf");
	if (!cfg)
	cfg = ast_config_load("res_speech_unimrcp.conf");
	if (!cfg)
	cfg = ast_config_load(UNI_ENGINE_CONFIG);
#endif

	if(!cfg) {
		ast_log(LOG_WARNING, "No such configuration file %s\n", UNI_ENGINE_CONFIG);
		return FALSE;
	}
#if AST_VERSION_AT_LEAST(1,6,2)
	if(cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_ERROR, "Config file %s is in an invalid format\n", UNI_ENGINE_CONFIG);
		return FALSE;
	}
#endif

	if((value = ast_variable_retrieve(cfg, "general", "unimrcp-profile")) != NULL) {
		ast_log(LOG_DEBUG, "general.unimrcp-profile=%s\n", value);
		uni_engine.profile = apr_pstrdup(uni_engine.pool, value);
	}

	if((value = ast_variable_retrieve(cfg, "general", "log-level")) != NULL) {
		ast_log(LOG_DEBUG, "general.log-level=%s\n", value);
		uni_engine.log_level = apt_log_priority_translate(value);
	}

	if((value = ast_variable_retrieve(cfg, "general", "log-output")) != NULL) {
		ast_log(LOG_DEBUG, "general.log-output=%s\n", value);
		uni_engine.log_output = atoi(value);
	}

	if((value = ast_variable_retrieve(cfg, "general", "cancelifqueue")) != NULL) {
		ast_log(LOG_DEBUG, "general.cancelifqueue=%s\n", value);
		uni_engine.cancelifqueue = ast_true(value);
	}
  else
	uni_engine.cancelifqueue = TRUE;

	if((value = ast_variable_retrieve(cfg, "general", "startinputtimers")) != NULL) {
		ast_log(LOG_DEBUG, "general.startinputtimers=%s\n", value);
		uni_engine.startinputtimers = ast_true(value);
	}
	else
	uni_engine.startinputtimers = TRUE;

	if((value = ast_variable_retrieve(cfg, "general", "dtmfstopspeech")) != NULL) {
		ast_log(LOG_DEBUG, "general.dtmfstopspeech=%s\n", value);
		uni_engine.dtmfstopspeech = ast_true(value);
	}
	else
	uni_engine.dtmfstopspeech = FALSE;

  if((value = ast_variable_retrieve(cfg, "general", "returnnlsml")) != NULL) {
		ast_log(LOG_DEBUG, "general.returnnlsml=%s\n", value);
		uni_engine.returnnlsml = ast_true(value);
	}
	else
	uni_engine.returnnlsml = FALSE;

  if((value = ast_variable_retrieve(cfg, "general", "vendorspecificparameters")) != NULL) {
		ast_log(LOG_DEBUG, "general.vendorspecificparameters=%s\n", value);
		uni_engine.vendorspecificparameters = ast_true(value);
	}
  else
	uni_engine.vendorspecificparameters = FALSE;

  if((value = ast_variable_retrieve(cfg, "general", "setparams")) != NULL) {
		ast_log(LOG_DEBUG, "general.setparams=%s\n", value);
		uni_engine.setparams = ast_true(value);
	}
  else
	uni_engine.setparams = FALSE;

  if((value = ast_variable_retrieve(cfg, "general", "removeswi")) != NULL) {
		ast_log(LOG_DEBUG, "general.removeswi=%s\n", value);
		uni_engine.removeswi = ast_true(value);
	}
  else
	uni_engine.removeswi = FALSE;

  if((value = ast_variable_retrieve(cfg, "general", "setspeechlanguage")) != NULL) {
		ast_log(LOG_DEBUG, "general.setspeechlanguage=%s\n", value);
		uni_engine.setspeechlanguage = ast_true(value);
	}
  else
	uni_engine.setspeechlanguage = FALSE;

  if((value = ast_variable_retrieve(cfg, "general", "max")) != NULL) {
		ast_log(LOG_DEBUG, "general.max=%s\n", value);
		uni_engine.max_speech_sessions = atoi(value);
	}

  if((value = ast_variable_retrieve(cfg, "general", "binarygrammars")) != NULL) {
		ast_log(LOG_DEBUG, "general.binarygrammars=%s\n", value);
		uni_engine.binarygrammars = ast_true(value);
	}
  else
	uni_engine.binarygrammars = FALSE;


	uni_engine.grammars = uni_engine_grammars_load(cfg,"grammars",pool);

	uni_engine.v2_properties = uni_engine_properties_load(cfg,"mrcpv2-properties",MRCP_VERSION_2,pool);
	uni_engine.v1_properties = uni_engine_properties_load(cfg,"mrcpv1-properties",MRCP_VERSION_1,pool);

	ast_config_destroy(cfg);
	return TRUE;
}

/** \brief Unload UniMRCP engine */
static apt_bool_t uni_engine_unload()
{
	if(uni_engine.client) {
    mrcp_client_shutdown(uni_engine.client);
		mrcp_client_destroy(uni_engine.client);
		uni_engine.client = NULL;
	}

	/* Destroy singleton logger */
	apt_log_instance_destroy();

	if(uni_engine.mutex) {
		apr_thread_mutex_destroy(uni_engine.mutex);
		uni_engine.mutex = NULL;
	}

	if(uni_engine.pool) {
		apr_pool_destroy(uni_engine.pool);
		uni_engine.pool = NULL;
	}

 	/* APR global termination */
	apr_terminate();

	return TRUE;
}

/** \brief Load UniMRCP engine */
static apt_bool_t uni_engine_load()
{
	apr_pool_t *pool;
	apt_dir_layout_t *dir_layout;

	/* APR global initialization */
	if(apr_initialize() != APR_SUCCESS) {
		ast_log(LOG_ERROR, "Failed to initialize APR\n");
		return FALSE;
	}

	uni_engine.pool = NULL;
	uni_engine.client = NULL;
	uni_engine.application = NULL;
	uni_engine.profile = NULL;
	uni_engine.log_level = APT_PRIO_INFO;
	uni_engine.log_output = APT_LOG_OUTPUT_CONSOLE | APT_LOG_OUTPUT_FILE;
	uni_engine.grammars = NULL;
	uni_engine.v2_properties = NULL;
	uni_engine.v1_properties = NULL;
	uni_engine.mutex = NULL;
	uni_engine.current_speech_index = 0;
	uni_engine.current_speech_sessions = 0;
	uni_engine.max_speech_sessions = 240;

  uni_engine.cancelifqueue = TRUE; // option for Vestec
  uni_engine.startinputtimers = TRUE;
  uni_engine.dtmfstopspeech = FALSE;
  uni_engine.returnnlsml = FALSE; // Pass NLSML XML file tmp reference as result
  uni_engine.vendorspecificparameters = FALSE; // option for Nuance
  uni_engine.setparams = FALSE; // option for Nuance
  uni_engine.removeswi = FALSE; // option for Nuance
  uni_engine.setspeechlanguage = FALSE;
  uni_engine.binarygrammars = FALSE; // option for Nuance

	pool = apt_pool_create();
	if(!pool) {
		ast_log(LOG_ERROR, "Failed to create APR pool\n");
		uni_engine_unload();
		return FALSE;
	}

	uni_engine.pool = pool;
	uni_engine.v2_properties = NULL;
	uni_engine.v1_properties = NULL;
			
	if(apr_thread_mutex_create(&uni_engine.mutex, APR_THREAD_MUTEX_DEFAULT, pool) != APR_SUCCESS) {
		ast_log(LOG_ERROR, "Failed to create engine mutex\n");
		uni_engine_unload();
		return FALSE;
	}


	/* Load engine configuration */
	uni_engine_config_load(pool);

	if(!uni_engine.profile) {
		uni_engine.profile = "uni2";
	}

	dir_layout = apt_default_dir_layout_create(UNIMRCP_DIR_LOCATION,pool);
	/* Create singleton logger */
	apt_log_instance_create(uni_engine.log_output, uni_engine.log_level, pool);
	if(apt_log_output_mode_check(APT_LOG_OUTPUT_FILE) == TRUE) {
#ifdef OPAQUE_DIR_LAYOUT
		const char *log_dir_path = apt_dir_layout_path_get(dir_layout,APT_LAYOUT_LOG_DIR);
#else
		const char *log_dir_path = dir_layout->log_dir_path;
#endif
	  /* Open the log file */
		apt_log_file_open(log_dir_path,"astuni",MAX_LOG_FILE_SIZE,MAX_LOG_FILE_COUNT,TRUE,pool);
  }

	uni_engine.client = unimrcp_client_create(dir_layout);
	if(uni_engine.client) {
		uni_engine.application = mrcp_application_create(
										uni_message_handler,
										&uni_engine,
										pool);
		if(uni_engine.application) {
			mrcp_client_application_register(
							uni_engine.client,
							uni_engine.application,
							"ASTMRCP");
		}
	}

	if(!uni_engine.client || !uni_engine.application) {
		ast_log(LOG_ERROR, "Failed to initialize MRCP client\n");
		uni_engine_unload();
		return FALSE;
	}

	return TRUE;
}

/** \brief Load module */
static int load_module(void)
{
	ast_log(LOG_NOTICE, "Load Res-Speech-UniMRCP module\n");

	if(uni_engine_load() == FALSE) {
		return AST_MODULE_LOAD_FAILURE;
	}

	if(mrcp_client_start(uni_engine.client) != TRUE) {
		ast_log(LOG_ERROR, "Failed to start MRCP client\n");
		uni_engine_unload();
		return AST_MODULE_LOAD_FAILURE;
	}

#if AST_VERSION_AT_LEAST(10,0,0)

#if AST_VERSION_AT_LEAST(13,0,0)
	ast_engine.formats = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_DEFAULT);
#elif AST_VERSION_AT_LEAST(12,0,0)
	ast_engine.formats = ast_format_cap_alloc(AST_FORMAT_CAP_FLAG_NOLOCK);
#else /* <= 11 */
	ast_engine.formats = ast_format_cap_alloc_nolock();
#endif
	if(!ast_engine.formats) {
		ast_log(LOG_ERROR, "Failed to alloc media format capabilities\n");
		uni_engine_unload();
		return AST_MODULE_LOAD_FAILURE;
	}
#if AST_VERSION_AT_LEAST(13,0,0)
	ast_format_cap_append(ast_engine.formats, ast_format_slin, 0);
#else
	struct ast_format format;
	ast_format_set(&format, AST_FORMAT_SLINEAR, 0);
	ast_format_cap_add(ast_engine.formats, &format);
#endif

#else /* <= 1.8 */
	ast_engine.formats = AST_FORMAT_SLINEAR;
#endif

	if(ast_speech_register(&ast_engine)) {
		ast_log(LOG_ERROR, "Failed to register module\n");
		mrcp_client_shutdown(uni_engine.client);
		uni_engine_unload();
		return AST_MODULE_LOAD_FAILURE;
	}

  if (strchr(uni_engine.profile, ','))
  {
    char configured_profile[255] = "";
    char *profile = NULL;
    char *profile_end = NULL;
    struct ast_speech_engine *ast_engine_profile;
    char *name;

    strncpy(configured_profile, uni_engine.profile, sizeof(configured_profile));
    profile = configured_profile;

    do
    {
      profile_end = strchr(profile, ',');
      if (profile_end)
      {
        *profile_end = 0;
      }

  	  ast_log(LOG_NOTICE, "Profile = %s\n", profile);

      ast_engine_profile = ast_calloc(sizeof(struct ast_speech_engine), 1);
      if (ast_engine_profile)
      {
        memcpy(ast_engine_profile, &ast_engine, sizeof(struct ast_speech_engine));

        name = apr_palloc(uni_engine.pool,100);
        if (name)
        {
          sprintf(name, "%s:%s", UNI_ENGINE_NAME, profile);
          ast_engine_profile->name = name;
	        if(ast_speech_register(ast_engine_profile)) {
		        ast_log(LOG_ERROR, "Failed to register module %s\n", name);
            ast_free(name);
            ast_free(ast_engine_profile);
		      }
        }
        else
        {
		      ast_log(LOG_ERROR, "Failed to register module %s\n", name);
          ast_free(ast_engine_profile);
        }
	    }

      if (profile_end)
      profile_end++;

      profile = profile_end;
    }
    while (profile_end);
  }

	return AST_MODULE_LOAD_SUCCESS;
}

/** \brief Unload module */
static int unload_module(void)
{
	ast_log(LOG_NOTICE, "Unload Res-Speech-UniMRCP module\n");
	if(ast_speech_unregister(UNI_ENGINE_NAME)) {
		ast_log(LOG_ERROR, "Failed to unregister module\n");
	}

  if (strchr(uni_engine.profile, ','))
  {
    char configured_profile[255] = "";
    char *profile = NULL;
    char *profile_end = NULL;
    char *name;

    strncpy(configured_profile, uni_engine.profile, sizeof(configured_profile));
    profile = configured_profile;

    do
    {
      profile_end = strchr(profile, ',');
      if (profile_end)
      {
        *profile_end = 0;
      }

  	  ast_log(LOG_NOTICE, "Profile = %s\n", profile);

      name = ast_calloc(100, 1);
      if (name)
      {
        sprintf(name, "%s:%s", UNI_ENGINE_NAME, profile);
	      if(ast_speech_unregister(name)) {
		      ast_log(LOG_ERROR, "Failed to unregister module %s\n", name);
	      }
        ast_free(name);
	    }

      if (profile_end)
      profile_end++;

      profile = profile_end;
    }
    while (profile_end);
  }

	if(uni_engine.client) {
		mrcp_client_shutdown(uni_engine.client);
	}

	if(uni_engine.v1_properties) {
    mrcp_message_header_destroy(uni_engine.v1_properties);
	}

  if(uni_engine.v2_properties){
    mrcp_message_header_destroy(uni_engine.v2_properties);
	}

	uni_engine_unload();
	return 0;
}

// Allows load module build in a different environment
#undef AST_BUILDOPT_SUM
#define AST_BUILDOPT_SUM ""

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "UniMRCP Speech Engine");
