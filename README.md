#uniMRCP for Asterisk
====================

This is a fork of the original project asterisk-unimrcp.
https://github.com/unispeech/asterisk-unimrcp

* Generic Speech Recognition API

The module res_speech_unimrcp.so is an implementation of the Generic Speech Recognition API of
Asterisk based on the UniMRCP client library.

* Dialplan Applications

The module app_unimrcp.so is a suite of speech recognition and synthesis applications for Asterisk

* We added extra features for (used by the Voximal VoiceXML browser) :

- multi engines (enable to use more than one TTS engine).
- set properties (set properties to the ASR engine, from Asterisk Dialplan).
- bultin language support (can change the default)
- binary Nuance grammars
- return of the NLSML full xml answer (to be parsed by our browser).
- DTMF support by the ASR engine
- for SSML, a way to maintain the session to avoid open/close for each text.
- volume adjustment to be able to mix prerecorded audio with TTS (without volume changes).
- save the TTS audio flow to be able to replay it (cache option).

* Files modified :

- res_speech_unimrcp.c
- res-speech-unimrcp/res_speech_unimrcp.c
- app-unimrcp/app_unimrcp.c
- app-unimrcp/app_mrcpsynth.c
- app-unimrcp/ast_unimrcp_framework.c
- app-unimrcp/ast_compat_defs.h


##Requirements
------------

Any Asterisk version from 1.6 to the last one.


##License
-------

Since Asterisk is distributed under the GPLv2 license, and the UniMRCP modules are loaded by and
directly interface with Asterisk, the GPLv2 license applies to the UniMRCP modules too.

This module is licensed under the GPLv2, feel free to redistribute, modify and
contribute changes.

A copy of the GPLv2 license text should be included with the module. If not,
check out the github repository at https://github.com/voximal/asterisk-macros
or one of its clones.

The license text can also be downloaded from:
https://www.gnu.org/licenses/gpl-2.0.txt


##Help us improve the support!
----------------------------

Found an issue? Solved one? Added something that was missing? Help us make it better!

Developed by [@achaloyan](https://github.com/unispeech)
Forked by [@voximal](https://github.com/voximal)
