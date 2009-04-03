/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "deliver.h"
#include "array.h"
#include "hostpid.h"
#include "istream.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "deliver-settings.h"

#include <stddef.h>
#include <stdlib.h>

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct deliver_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct deliver_settings, field), defines }

static struct setting_define deliver_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEF(SET_STR, log_path),
	DEF(SET_STR, info_log_path),
	DEF(SET_STR, log_timestamp),
	DEF(SET_STR, syslog_facility),
	DEF(SET_BOOL, version_ignore),
	DEF(SET_UINT, umask),

	DEF(SET_STR, mail_plugins),
	DEF(SET_STR, mail_plugin_dir),

	DEF(SET_STR, mail_uid),
	DEF(SET_STR, mail_gid),
	DEF(SET_STR, mail_chroot),
	DEF(SET_STR, mail_access_groups),

	DEF(SET_STR, postmaster_address),
	DEF(SET_STR, hostname),
	DEF(SET_STR, sendmail_path),
	DEF(SET_STR, rejection_subject),
	DEF(SET_STR, rejection_reason),
	DEF(SET_STR, auth_socket_path),
	DEF(SET_STR, deliver_log_format),
	DEF(SET_BOOL, quota_full_tempfail),

	{ SET_STRLIST, "plugin", offsetof(struct deliver_settings, plugin_envs), NULL },

	SETTING_DEFINE_LIST_END
};

static struct deliver_settings deliver_default_settings = {
	MEMBER(base_dir) PKG_RUNDIR,
	MEMBER(log_path) "",
	MEMBER(info_log_path) "",
	MEMBER(log_timestamp) DEFAULT_FAILURE_STAMP_FORMAT,
	MEMBER(syslog_facility) "mail",
	MEMBER(version_ignore) FALSE,
	MEMBER(umask) 0077,

	MEMBER(mail_plugins) "",
	MEMBER(mail_plugin_dir) MODULEDIR"/lda",

	MEMBER(mail_uid) "",
	MEMBER(mail_gid) "",
	MEMBER(mail_chroot) "",
	MEMBER(mail_access_groups) "",

	MEMBER(postmaster_address) "",
	MEMBER(hostname) "",
	MEMBER(sendmail_path) "/usr/lib/sendmail",
	MEMBER(rejection_subject) "Rejected: %s",
	MEMBER(rejection_reason)
		"Your message to <%t> was automatically rejected:%n%r",
	MEMBER(auth_socket_path) "auth-master",
	MEMBER(deliver_log_format) "msgid=%m: %$",
	MEMBER(quota_full_tempfail) FALSE
};

struct setting_parser_info deliver_setting_parser_info = {
	MEMBER(defines) deliver_setting_defines,
	MEMBER(defaults) &deliver_default_settings,

	MEMBER(parent) NULL,
	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct deliver_settings)
};

static pool_t settings_pool = NULL;

static void fix_base_path(struct deliver_settings *set, const char **str)
{
	if (*str != NULL && **str != '\0' && **str != '/') {
		*str = p_strconcat(settings_pool,
				   set->base_dir, "/", *str, NULL);
	}
}

struct setting_parser_context *
deliver_settings_read(struct deliver_settings **set_r,
		      struct mail_user_settings **user_set_r)
{
	static const struct setting_parser_info *roots[] = {
                &deliver_setting_parser_info,
                &mail_user_setting_parser_info
	};
	void **sets;
	struct deliver_settings *deliver_set;
	struct setting_parser_context *parser;

	if (settings_pool == NULL)
		settings_pool = pool_alloconly_create("deliver settings", 1024);
	else
		p_clear(settings_pool);

	mail_storage_namespace_defines_init(settings_pool);

	parser = settings_parser_init_list(settings_pool,
				roots, N_ELEMENTS(roots),
				SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);

	if (settings_parse_environ(parser) < 0) {
		i_fatal_status(EX_CONFIG, "Error reading configuration: %s",
			       settings_parser_get_error(parser));
	}

	sets = settings_parser_get_list(parser);

	deliver_set = sets[0];
	if (*deliver_set->hostname == '\0')
		deliver_set->hostname = my_hostname;
	fix_base_path(deliver_set, &deliver_set->auth_socket_path);

	if (*deliver_set->postmaster_address == '\0') {
		i_fatal_status(EX_CONFIG,
			       "postmaster_address setting not given");
	}

	*set_r = deliver_set;
	*user_set_r = sets[1];
	return parser;
}

void deliver_settings_add(struct setting_parser_context *parser,
			  const ARRAY_TYPE(const_string) *extra_fields)
{
	const char *const *str, *p, *line;
	unsigned int i, count;

	str = array_get(extra_fields, &count);
	for (i = 0; i < count; i++) T_BEGIN {
		p = strchr(str[i], '=');
		if (p != NULL)
			line = str[i];
		else
			line = t_strconcat(str[i], "=yes", NULL);
		if (settings_parse_line(parser, str[i]) < 0) {
			i_fatal_status(EX_CONFIG,
				       "Invalid userdb input '%s': %s", str[i],
				       settings_parser_get_error(parser));
		}
	} T_END;

}
