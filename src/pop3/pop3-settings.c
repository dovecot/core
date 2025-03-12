/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "pop3-settings.h"
#include "var-expand.h"

#include <unistd.h>

static bool pop3_settings_verify(void *_set, pool_t pool,
				 const char **error_r);

struct service_settings pop3_service_settings = {
	.name = "pop3",
	.protocol = "pop3",
	.type = "",
	.executable = "pop3",
	.user = "",
	.group = "",
	.privileged_group = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1024,
	.client_limit = 1,
#ifdef DOVECOT_PRO_EDITION
	.restart_request_count = 1000,
#else
	.restart_request_count = 1,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue pop3_service_settings_defaults[] = {
	{ "unix_listener", "login\\spop3 srv.pop3\\s%{pid}" },

	{ "unix_listener/login\\spop3/path", "login/pop3" },
	{ "unix_listener/login\\spop3/mode", "0666" },

	{ "unix_listener/srv.pop3\\s%{pid}/path", "srv.pop3/%{pid}" },
	{ "unix_listener/srv.pop3\\s%{pid}/type", "admin" },
	{ "unix_listener/srv.pop3\\s%{pid}/mode", "0600" },

	{ "service_extra_groups", "$SET:default_internal_group" },

	{ NULL, NULL }
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct pop3_settings)

static const struct setting_define pop3_setting_defines[] = {
	DEF(BOOL, verbose_proctitle),
	DEF(STR, rawlog_dir),

	DEF(BOOL, pop3_no_flag_updates),
	DEF(BOOL, pop3_enable_last),
	DEF(BOOL, pop3_reuse_xuidl),
	DEF(BOOL, pop3_save_uidl),
	DEF(BOOL, pop3_lock_session),
	DEF(BOOL, pop3_fast_size_lookups),
	DEF(BOOLLIST, pop3_client_workarounds),
	DEF(STR_NOVARS, pop3_logout_format),
	DEF(ENUM, pop3_uidl_duplicates),
	DEF(STR, pop3_deleted_flag),
	DEF(ENUM, pop3_delete_type),

	SETTING_DEFINE_LIST_END
};

static const struct pop3_settings pop3_default_settings = {
	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,
	.rawlog_dir = "",

	.pop3_no_flag_updates = FALSE,
	.pop3_enable_last = FALSE,
	.pop3_reuse_xuidl = FALSE,
	.pop3_save_uidl = FALSE,
	.pop3_lock_session = FALSE,
	.pop3_fast_size_lookups = FALSE,
	.pop3_client_workarounds = ARRAY_INIT,
	.pop3_logout_format =
		"top=%{top_count}/%{top_bytes}, "
		"retr=%{retr_count}/%{retr_bytes}, "
		"del=%{deleted_count}/%{deleted_bytes}, "
		"size=%{message_bytes}",
	.pop3_uidl_duplicates = "allow:rename",
	.pop3_deleted_flag = "",
	.pop3_delete_type = "default:expunge:flag"
};

static const struct setting_keyvalue pop3_default_settings_keyvalue[] = {
#ifdef DOVECOT_PRO_EDITION
	{ "service/pop3/process_shutdown_filter", "event=mail_user_session_finished AND rss > 20MB" },
#endif
	{ NULL, NULL },
};

const struct setting_parser_info pop3_setting_parser_info = {
	.name = "pop3",

	.defines = pop3_setting_defines,
	.defaults = &pop3_default_settings,
	.default_settings = pop3_default_settings_keyvalue,

	.struct_size = sizeof(struct pop3_settings),
	.pool_offset1 = 1 + offsetof(struct pop3_settings, pool),
	.check_func = pop3_settings_verify,
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

	str = settings_boollist_get(&set->pop3_client_workarounds);
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
	if (strcmp(set->pop3_delete_type, "default") == 0) {
		if (set->pop3_deleted_flag[0] == '\0')
			set->parsed_delete_type = POP3_DELETE_TYPE_EXPUNGE;
		else
			set->parsed_delete_type = POP3_DELETE_TYPE_FLAG;
	} else if (strcmp(set->pop3_delete_type, "expunge") == 0) {
		set->parsed_delete_type = POP3_DELETE_TYPE_EXPUNGE;
	} else if (strcmp(set->pop3_delete_type, "flag") == 0) {
		if (set->pop3_deleted_flag[0] == '\0') {
			*error_r = "pop3_delete_type=flag, but pop3_deleted_flag not set";
			return FALSE;
		}
		set->parsed_delete_type = POP3_DELETE_TYPE_FLAG;
	} else {
		*error_r = t_strdup_printf("pop3_delete_type: Unknown value '%s'",
					   set->pop3_delete_type);
		return FALSE;
	}

	struct var_expand_program *prog;
	const char *error;
	if (var_expand_program_create(set->pop3_logout_format, &prog, &error) < 0) {
		*error_r = t_strdup_printf("Invalid pop3_logout_format: %s", error);
		return FALSE;
	}
	const char *const *vars = var_expand_program_variables(prog);
	set->parsed_want_uidl_change = str_array_find(vars, "uidl_change");
	var_expand_program_free(&prog);

	return TRUE;
}
/* </settings checks> */
