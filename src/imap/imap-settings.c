/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "imap-settings.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct imap_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct imap_settings, field), defines }

static struct setting_define imap_setting_defines[] = {
	DEF(SET_BOOL, mail_debug),
	DEF(SET_BOOL, shutdown_clients),

	DEF(SET_UINT, imap_max_line_length),
	DEF(SET_UINT, imap_idle_notify_interval),
	DEF(SET_STR, imap_capability),
	DEF(SET_STR, imap_client_workarounds),
	DEF(SET_STR, imap_logout_format),
	DEF(SET_STR, imap_id_send),
	DEF(SET_STR, imap_id_log),

	SETTING_DEFINE_LIST_END
};

static struct imap_settings imap_default_settings = {
	MEMBER(mail_debug) FALSE,
	MEMBER(shutdown_clients) FALSE,

	/* RFC-2683 recommends at least 8000 bytes. Some clients however don't
	   break large message sets to multiple commands, so we're pretty
	   liberal by default. */
	MEMBER(imap_max_line_length) 65536,
	MEMBER(imap_idle_notify_interval) 120,
	MEMBER(imap_capability) "",
	MEMBER(imap_client_workarounds) "outlook-idle",
	MEMBER(imap_logout_format) "bytes=%i/%o",
	MEMBER(imap_id_send) "",
	MEMBER(imap_id_log) ""
};

static struct setting_parser_info *imap_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};

struct setting_parser_info imap_setting_parser_info = {
	MEMBER(defines) imap_setting_defines,
	MEMBER(defaults) &imap_default_settings,

	MEMBER(parent) NULL,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct imap_settings),
	MEMBER(check_func) NULL,
	MEMBER(dependencies) imap_setting_dependencies
};
