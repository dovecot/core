/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "imap-settings.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

static bool imap_settings_verify(void *_set, pool_t pool,
				 const char **error_r);

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct imap_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct imap_settings, field), defines }

static const struct setting_define imap_setting_defines[] = {
	DEF(SET_BOOL, mail_debug),

	DEF(SET_UINT, imap_max_line_length),
	DEF(SET_UINT, imap_idle_notify_interval),
	DEF(SET_STR, imap_capability),
	DEF(SET_STR, imap_client_workarounds),
	DEF(SET_STR, imap_logout_format),
	DEF(SET_STR, imap_id_send),
	DEF(SET_STR, imap_id_log),

	SETTING_DEFINE_LIST_END
};

static const struct imap_settings imap_default_settings = {
	MEMBER(mail_debug) FALSE,

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

static const struct setting_parser_info *imap_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};

const struct setting_parser_info imap_setting_parser_info = {
	MEMBER(module_name) "imap",
	MEMBER(defines) imap_setting_defines,
	MEMBER(defaults) &imap_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct imap_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) NULL,

	MEMBER(check_func) imap_settings_verify,
	MEMBER(dependencies) imap_setting_dependencies
};

/* <settings checks> */
struct imap_client_workaround_list {
	const char *name;
	enum imap_client_workarounds num;
};

static const struct imap_client_workaround_list imap_client_workaround_list[] = {
	{ "delay-newmail", WORKAROUND_DELAY_NEWMAIL },
	{ "outlook-idle", 0 }, /* only for backwards compatibility */
	{ "netscape-eoh", WORKAROUND_NETSCAPE_EOH },
	{ "tb-extra-mailbox-sep", WORKAROUND_TB_EXTRA_MAILBOX_SEP },
	{ NULL, 0 }
};

static int
imap_settings_parse_workarounds(struct imap_settings *set,
				const char **error_r)
{
        enum imap_client_workarounds client_workarounds = 0;
        const struct imap_client_workaround_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->imap_client_workarounds, " ,");
	for (; *str != NULL; str++) {
		list = imap_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("imap_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}


static bool
imap_settings_verify(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct imap_settings *set = _set;

	if (imap_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;
	return TRUE;
}
/* </settings checks> */
