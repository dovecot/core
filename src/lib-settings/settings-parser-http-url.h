#ifndef SETTINGS_PARSER_HTTP_URL_H
#define SETTINGS_PARSER_HTTP_URL_H

#include "settings-parser.h"
#include "http-url.h"

/* SET_HTTP_URL / SET_HTTP_URL_AUTH struct members are stored as a
   struct http_url by value. The only supported default is unset: use
   HTTP_URL_INIT_EMPTY in a _default_settings initializer. A non-empty
   struct http_url literal default cannot be hand-maintained; use
   setting_parser_info.default_settings instead, whose string values go
   through the normal parse path. */
#define SETTING_DEFINE_STRUCT_HTTP_URL(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_HTTP_URL, 0, struct http_url, key, name, struct_name)
#define SETTING_DEFINE_STRUCT_HTTP_URL_AUTH(key, name, struct_name) \
	SETTING_DEFINE_STRUCT_TYPE(SET_HTTP_URL_AUTH, 0, struct http_url, key, name, struct_name)

#endif
