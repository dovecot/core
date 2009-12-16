/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "pop3-settings.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

static bool pop3_settings_verify(void *_set, pool_t pool,
				 const char **error_r);

/* <settings checks> */
static struct file_listener_settings pop3_unix_listeners_array[] = {
	{ "login/pop3", 0666, "", "" }
};
static struct file_listener_settings *pop3_unix_listeners[] = {
	&pop3_unix_listeners_array[0]
};
static buffer_t pop3_unix_listeners_buf = {
	pop3_unix_listeners, sizeof(pop3_unix_listeners), { 0, }
};
/* </settings checks> */

struct service_settings pop3_service_settings = {
	.name = "pop3",
	.protocol = "pop3",
	.type = "",
	.executable = "pop3",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1024,
	.client_limit = 0,
	.service_count = 1,
	.vsz_limit = -1U,

	.unix_listeners = { { &pop3_unix_listeners_buf,
			      sizeof(pop3_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct pop3_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct pop3_settings, field), defines }

static const struct setting_define pop3_setting_defines[] = {
	DEF(SET_BOOL, mail_debug),
	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_BOOL, pop3_no_flag_updates),
	DEF(SET_BOOL, pop3_enable_last),
	DEF(SET_BOOL, pop3_reuse_xuidl),
	DEF(SET_BOOL, pop3_save_uidl),
	DEF(SET_BOOL, pop3_lock_session),
	DEF(SET_STR, pop3_client_workarounds),
	DEF(SET_STR, pop3_logout_format),

	SETTING_DEFINE_LIST_END
};

static const struct pop3_settings pop3_default_settings = {
	.mail_debug = FALSE,
	.verbose_proctitle = FALSE,

	.pop3_no_flag_updates = FALSE,
	.pop3_enable_last = FALSE,
	.pop3_reuse_xuidl = FALSE,
	.pop3_save_uidl = FALSE,
	.pop3_lock_session = FALSE,
	.pop3_client_workarounds = "",
	.pop3_logout_format = "top=%t/%p, retr=%r/%b, del=%d/%m, size=%s"
};

static const struct setting_parser_info *pop3_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};

const struct setting_parser_info pop3_setting_parser_info = {
	.module_name = "pop3",
	.defines = pop3_setting_defines,
	.defaults = &pop3_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct pop3_settings),

	.parent_offset = (size_t)-1,

	.check_func = pop3_settings_verify,
	.dependencies = pop3_setting_dependencies
};

/* <settings checks> */
struct pop3_client_workaround_list {
	const char *name;
	enum pop3_client_workarounds num;
};

static const struct pop3_client_workaround_list pop3_client_workaround_list[] = {
	{ "outlook-no-nuls", WORKAROUND_OUTLOOK_NO_NULS },
	{ "oe-ns-eoh", WORKAROUND_OE_NS_EOH },
	{ NULL, 0 }
};

static int
pop3_settings_parse_workarounds(struct pop3_settings *set,
				const char **error_r)
{
        enum pop3_client_workarounds client_workarounds = 0;
	const struct pop3_client_workaround_list *list;
	const char *const *str;

        str = t_strsplit_spaces(set->pop3_client_workarounds, " ,");
	for (; *str != NULL; str++) {
		list = pop3_client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("pop3_client_workarounds: "
				"Unknown workaround: %s", *str);
			return -1;
		}
	}
	set->parsed_workarounds = client_workarounds;
	return 0;
}

static bool
pop3_settings_verify(void *_set, pool_t pool ATTR_UNUSED, const char **error_r)
{
	struct pop3_settings *set = _set;

	if (pop3_settings_parse_workarounds(set, error_r) < 0)
		return FALSE;
	return TRUE;
}
/* </settings checks> */
