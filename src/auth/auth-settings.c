/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash-method.h"
#include "settings.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "service-settings.h"
#include "auth-settings.h"

static bool auth_settings_ext_check(struct event *event, void *_set, pool_t pool, const char **error_r);
static bool auth_passdb_settings_check(void *_set, pool_t pool, const char **error_r);
static bool auth_userdb_settings_check(void *_set, pool_t pool, const char **error_r);

struct service_settings auth_service_settings = {
	.name = "auth",
	.protocol = "",
	.type = "",
	.executable = "auth",
	.user = "$SET:default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 1,
#ifdef DOVECOT_PRO_EDITION
	.client_limit = 16384,
#endif

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};

const struct setting_keyvalue auth_service_settings_defaults[] = {
	{ "unix_listener", "auth-client auth-login auth-master auth-userdb login\\slogin token-login\\stokenlogin" },

	{ "unix_listener/auth-client/path", "auth-client" },
	{ "unix_listener/auth-client/type", "auth" },
	{ "unix_listener/auth-client/mode", "0600" },
	{ "unix_listener/auth-client/user", "$SET:default_internal_user" },

	{ "unix_listener/auth-login/path", "auth-login" },
	{ "unix_listener/auth-login/type", "login" },
	{ "unix_listener/auth-login/mode", "0600" },
	{ "unix_listener/auth-login/user", "$SET:default_internal_user" },

	{ "unix_listener/auth-master/path", "auth-master" },
	{ "unix_listener/auth-master/type", "master" },
	{ "unix_listener/auth-master/mode", "0600" },

	{ "unix_listener/auth-userdb/path", "auth-userdb" },
	{ "unix_listener/auth-userdb/type", "userdb" },
	{ "unix_listener/auth-userdb/mode", "0666" },
	{ "unix_listener/auth-userdb/user", "$SET:default_internal_user" },
	{ "unix_listener/auth-userdb/group", "$SET:default_internal_group" },

	{ "unix_listener/login\\slogin/path", "login/login" },
	{ "unix_listener/login\\slogin/type", "login" },
	{ "unix_listener/login\\slogin/mode", "0666" },

	{ "unix_listener/token-login\\stokenlogin/path", "token-login/tokenlogin" },
	{ "unix_listener/token-login\\stokenlogin/type", "token-login" },
	{ "unix_listener/token-login\\stokenlogin/mode", "0666" },

	{ NULL, NULL }
};

struct service_settings auth_worker_service_settings = {
	.name = "auth-worker",
	.protocol = "",
	.type = "worker",
	.executable = "auth -w",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_limit = 30,
	.client_limit = 1,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_keyvalue auth_worker_service_settings_defaults[] = {
	{ "unix_listener", "auth-worker" },

	{ "unix_listener/auth-worker/path", "auth-worker" },
	{ "unix_listener/auth-worker/mode", "0600" },
	{ "unix_listener/auth-worker/user", "$SET:default_internal_user" },

	{ NULL, NULL }
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("passdb_"#name, name, struct auth_passdb_settings)

static const struct setting_define auth_passdb_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, driver),
	DEF(BOOL, fields_import_all),
	DEF(BOOLLIST, mechanisms_filter),
	DEF(STR, username_filter),

	DEF(STR, default_password_scheme),

	DEF(ENUM, skip),
	DEF(ENUM, result_success),
	DEF(ENUM, result_failure),
	DEF(ENUM, result_internalfail),

	DEF(BOOL, deny),
	DEF(BOOL, master),
	DEF(BOOL, use_cache),
	DEF(BOOL, use_worker),

	SETTING_DEFINE_LIST_END
};

static const struct auth_passdb_settings auth_passdb_default_settings = {
	.name = "",
	.driver = "",
	.fields_import_all = TRUE,
	.mechanisms_filter = ARRAY_INIT,
	.username_filter = "",

	.default_password_scheme = "PLAIN",

	.skip = "never:authenticated:unauthenticated",
	.result_success = "return-ok:return:return-fail:continue:continue-ok:continue-fail",
	.result_failure = "continue:return:return-ok:return-fail:continue-ok:continue-fail",
	.result_internalfail = "continue:return:return-ok:return-fail:continue-ok:continue-fail",

	.deny = FALSE,
	.master = FALSE,
	.use_cache = TRUE,
	.use_worker = FALSE,
};

const struct setting_parser_info auth_passdb_setting_parser_info = {
	.name = "auth_passdb",

	.defines = auth_passdb_setting_defines,
	.defaults = &auth_passdb_default_settings,

	.struct_size = sizeof(struct auth_passdb_settings),
	.pool_offset1 = 1 + offsetof(struct auth_passdb_settings, pool),

	.check_func = auth_passdb_settings_check
};

static const struct setting_define auth_passdb_post_setting_defines[] = {
	{ .type = SET_STRLIST, .key = "passdb_fields",
	  .offset = offsetof(struct auth_passdb_post_settings, fields) },

	SETTING_DEFINE_LIST_END
};

static const struct auth_passdb_post_settings auth_passdb_post_default_settings = {
	.fields = ARRAY_INIT,
};

const struct setting_parser_info auth_passdb_post_setting_parser_info = {
	.name = "auth_passdb_post",

	.defines = auth_passdb_post_setting_defines,
	.defaults = &auth_passdb_post_default_settings,

	.struct_size = sizeof(struct auth_passdb_post_settings),
	.pool_offset1 = 1 + offsetof(struct auth_passdb_post_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("userdb_"#name, name, struct auth_userdb_settings)

static const struct setting_define auth_userdb_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, driver),
	DEF(BOOL, fields_import_all),

	DEF(ENUM, skip),
	DEF(ENUM, result_success),
	DEF(ENUM, result_failure),
	DEF(ENUM, result_internalfail),

	DEF(BOOL, use_cache),
	DEF(BOOL, use_worker),

	SETTING_DEFINE_LIST_END
};

static const struct auth_userdb_settings auth_userdb_default_settings = {
	/* NOTE: when adding fields, update also auth.c:userdb_dummy_set */
	.name = "",
	.driver = "",
	.fields_import_all = TRUE,

	.skip = "never:found:notfound",
	.result_success = "return-ok:return:return-fail:continue:continue-ok:continue-fail",
	.result_failure = "continue:return:return-ok:return-fail:continue-ok:continue-fail",
	.result_internalfail = "continue:return:return-ok:return-fail:continue-ok:continue-fail",

	.use_cache = TRUE,
	.use_worker = FALSE,
};

const struct setting_parser_info auth_userdb_setting_parser_info = {
	.name = "auth_userdb",

	.defines = auth_userdb_setting_defines,
	.defaults = &auth_userdb_default_settings,

	.struct_size = sizeof(struct auth_userdb_settings),
	.pool_offset1 = 1 + offsetof(struct auth_userdb_settings, pool),

	.check_func = auth_userdb_settings_check,
};

static const struct setting_define auth_userdb_post_setting_defines[] = {
	{ .type = SET_STRLIST, .key = "userdb_fields",
	  .offset = offsetof(struct auth_userdb_post_settings, fields) },

	SETTING_DEFINE_LIST_END
};

static const struct auth_userdb_post_settings auth_userdb_post_default_settings = {
	.fields = ARRAY_INIT,
};

const struct setting_parser_info auth_userdb_post_setting_parser_info = {
	.name = "auth_userdb_post",

	.defines = auth_userdb_post_setting_defines,
	.defaults = &auth_userdb_post_default_settings,

	.struct_size = sizeof(struct auth_userdb_post_settings),
	.pool_offset1 = 1 + offsetof(struct auth_userdb_post_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_static_settings)

static const struct setting_define auth_static_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_static", },
	{ .type = SET_FILTER_NAME, .key = "userdb_static", },
	DEF(STR, passdb_static_password),
	DEF(BOOL, userdb_static_allow_all_users),

	SETTING_DEFINE_LIST_END
};

static const struct auth_static_settings auth_static_default_settings = {
	.passdb_static_password = "",
	.userdb_static_allow_all_users = FALSE,
};

const struct setting_parser_info auth_static_setting_parser_info = {
	.name = "auth_static",

	.defines = auth_static_setting_defines,
	.defaults = &auth_static_default_settings,

	.struct_size = sizeof(struct auth_static_settings),
	.pool_offset1 = 1 + offsetof(struct auth_static_settings, pool),
};

/* we're kind of kludging here to avoid "auth_" prefix in the struct fields */
#undef DEF
#undef DEF_NOPREFIX
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("auth_"#name, name, struct auth_settings)
#define DEF_NOPREFIX(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_settings)

static const struct setting_define auth_setting_defines[] = {
	DEF(BOOLLIST, mechanisms),
	DEF(BOOLLIST, realms),
	DEF(STR, default_domain),
	DEF(SIZE, cache_size),
	DEF(TIME, cache_ttl),
	DEF(TIME, cache_negative_ttl),
	DEF(BOOL, cache_verify_password_with_worker),
	DEF(STR, username_chars),
	DEF(STR_HIDDEN, username_translation),
	DEF(STR_NOVARS, username_format),
	DEF(STR, master_user_separator),
	DEF(STR, anonymous_username),
#ifdef DOVECOT_PRO_EDITION
	DEF(STR_HIDDEN, krb5_keytab),
	DEF(STR_HIDDEN, gssapi_hostname),
	DEF(STR_HIDDEN, winbind_helper_path),
#else
	DEF(STR, krb5_keytab),
	DEF(STR, gssapi_hostname),
	DEF(STR, winbind_helper_path),
#endif
	DEF(STR, proxy_self),
	DEF(TIME, failure_delay),
	DEF(TIME_MSECS, internal_failure_delay),

	{ .type = SET_FILTER_NAME, .key = "auth_policy", },
	DEF(STR, policy_server_url),
	DEF(STR, policy_server_api_header),
	DEF(STR, policy_hash_mech),
	DEF(STR, policy_hash_nonce),
	DEF(BOOL, policy_reject_on_fail),
	DEF(BOOL, policy_check_before_auth),
	DEF(BOOL, policy_check_after_auth),
	DEF(BOOL, policy_report_after_auth),
	DEF(BOOL, policy_log_only),
	DEF(UINT_HIDDEN, policy_hash_truncate),

	DEF(BOOL, verbose),
	DEF(BOOL, debug),
	DEF(BOOL, debug_passwords),
	DEF(BOOL, allow_weak_schemes),
	DEF(STR, verbose_passwords),
	DEF(BOOL, ssl_require_client_cert),
	DEF(BOOL, ssl_username_from_cert),
#ifdef DOVECOT_PRO_EDITION
	DEF(BOOL_HIDDEN, use_winbind),
#else
	DEF(BOOL, use_winbind),
#endif

	{ .type = SET_FILTER_ARRAY, .key = "passdb",
	  .offset = offsetof(struct auth_settings, passdbs),
	  .filter_array_field_name = "passdb_name", },
	{ .type = SET_FILTER_ARRAY, .key = "userdb",
	  .offset = offsetof(struct auth_settings, userdbs),
	  .filter_array_field_name = "userdb_name", },

	DEF_NOPREFIX(STR_HIDDEN, base_dir),
	DEF_NOPREFIX(BOOL, verbose_proctitle),
	DEF_NOPREFIX(UINT, first_valid_uid),
	DEF_NOPREFIX(UINT, last_valid_uid),
	DEF_NOPREFIX(UINT, first_valid_gid),
	DEF_NOPREFIX(UINT, last_valid_gid),

	SETTING_DEFINE_LIST_END
};

static const struct auth_settings auth_default_settings = {
	.realms = ARRAY_INIT,
	.default_domain = "",
	.cache_size = 0,
	.cache_ttl = 60*60,
	.cache_negative_ttl = 60*60,
	.cache_verify_password_with_worker = FALSE,
	.username_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@",
	.username_translation = "",
	.username_format = "%{user | lower}",
	.master_user_separator = "",
	.anonymous_username = "anonymous",
	.krb5_keytab = "",
	.gssapi_hostname = "",
	.winbind_helper_path = "/usr/bin/ntlm_auth",
	.proxy_self = "",
	.failure_delay = 2,
	.internal_failure_delay = 2000,

	.policy_server_url = "",
	.policy_server_api_header = "",
	.policy_hash_mech = "sha256",
	.policy_hash_nonce = "",
	.policy_reject_on_fail = FALSE,
	.policy_check_before_auth = TRUE,
	.policy_check_after_auth = TRUE,
	.policy_report_after_auth = TRUE,
	.policy_log_only = FALSE,
	.policy_hash_truncate = 12,

	.verbose = FALSE,
	.debug = FALSE,
	.debug_passwords = FALSE,
	.allow_weak_schemes = FALSE,
	.verbose_passwords = "no",
	.ssl_require_client_cert = FALSE,
	.ssl_username_from_cert = FALSE,

	.use_winbind = FALSE,

	.passdbs = ARRAY_INIT,
	.userdbs = ARRAY_INIT,

	.base_dir = PKG_RUNDIR,
	.verbose_proctitle = VERBOSE_PROCTITLE_DEFAULT,
	.first_valid_uid = 500,
	.last_valid_uid = 0,
	.first_valid_gid = 1,
	.last_valid_gid = 0,
};
static const struct setting_keyvalue auth_default_settings_keyvalue[] = {
	{ "auth_mechanisms", "plain" },
	{ "auth_policy/http_client_request_absolute_timeout", "2s" },
	{ "auth_policy/http_client_max_idle_time", "10s" },
	{ "auth_policy/http_client_max_parallel_connections", "100" },
	{ "auth_policy/http_client_user_agent", "dovecot/auth-policy-client" },
	{ NULL, NULL }
};

const struct setting_parser_info auth_setting_parser_info = {
	.name = "auth",

	.defines = auth_setting_defines,
	.defaults = &auth_default_settings,
	.default_settings = auth_default_settings_keyvalue,

	.struct_size = sizeof(struct auth_settings),
	.pool_offset1 = 1 + offsetof(struct auth_settings, pool),
	.ext_check_func = auth_settings_ext_check,
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("auth_"#name, name, struct auth_policy_request_settings)

static const struct setting_define auth_policy_request_setting_defines[] = {
	DEF(STRLIST, policy_request_attributes),

	SETTING_DEFINE_LIST_END
};

static const struct auth_policy_request_settings auth_policy_request_default_settings = {
	.policy_request_attributes = ARRAY_INIT,
};
static const struct setting_keyvalue auth_policy_request_default_settings_keyvalue[] = {
	{ "auth_policy_request_attributes/login", "%{requested_username}" },
	{ "auth_policy_request_attributes/pwhash", "%{hashed_password}" },
	{ "auth_policy_request_attributes/remote", "%{remote_ip}" },
	{ "auth_policy_request_attributes/device_id", "%{client_id}" },
	{ "auth_policy_request_attributes/protocol", "%{protocol}" },
	{ "auth_policy_request_attributes/session_id", "%{session}" },
	{ "auth_policy_request_attributes/fail_type", "%{fail_type}" },
	{ NULL, NULL }
};

const struct setting_parser_info auth_policy_request_setting_parser_info = {
	.name = "auth_policy_request",

	.defines = auth_policy_request_setting_defines,
	.defaults = &auth_policy_request_default_settings,
	.default_settings = auth_policy_request_default_settings_keyvalue,

	.struct_size = sizeof(struct auth_policy_request_settings),
	.pool_offset1 = 1 + offsetof(struct auth_policy_request_settings, pool),
};

/* <settings checks> */
static bool
auth_settings_set_self_ips(struct auth_settings *set, pool_t pool,
			   const char **error_r)
{
	const char *const *tmp;
	ARRAY(struct ip_addr) ips_array;
	struct ip_addr *ips;
	unsigned int ips_count;
	int ret;

	if (*set->proxy_self == '\0') {
		set->proxy_self_ips = p_new(pool, struct ip_addr, 1);
		return TRUE;
	}

	p_array_init(&ips_array, pool, 4);
	tmp = t_strsplit_spaces(set->proxy_self, " ");
	for (; *tmp != NULL; tmp++) {
		ret = net_gethostbyname(*tmp, &ips, &ips_count);
		if (ret != 0) {
			*error_r = t_strdup_printf("auth_proxy_self_ips: "
				"gethostbyname(%s) failed: %s",
				*tmp, net_gethosterror(ret));
		}
		array_append(&ips_array, ips, ips_count);
	}
	array_append_zero(&ips_array);
	set->proxy_self_ips = array_front(&ips_array);
	return TRUE;
}

static bool
auth_verify_verbose_password(struct auth_settings *set,
			     const char **error_r)
{
	const char *p, *value = set->verbose_passwords;
	unsigned int num;

	p = strchr(value, ':');
	if (p != NULL) {
		if (str_to_uint(p+1, &num) < 0 || num == 0) {
			*error_r = t_strdup_printf("auth_verbose_passwords: "
				"Invalid truncation number: '%s'", p+1);
			return FALSE;
		}
		value = t_strdup_until(value, p);
	}
	if (strcmp(value, "no") == 0)
		return TRUE;
	else if (strcmp(value, "plain") == 0)
		return TRUE;
	else if (strcmp(value, "sha1") == 0)
		return TRUE;
	else if (strcmp(value, "yes") == 0) {
		/* just use it as alias for "plain" */
		set->verbose_passwords = "plain";
		return TRUE;
	} else {
		*error_r = "auth_verbose_passwords: Invalid value";
		return FALSE;
	}
}

static bool
auth_settings_get_passdbs(struct auth_settings *set, pool_t pool,
			  struct event *event, const char **error_r)
{
	const struct auth_passdb_settings *passdb_set;
	const char *passdb_name, *error;

	if (!array_is_created(&set->passdbs))
		return TRUE;

	p_array_init(&set->parsed_passdbs, pool, array_count(&set->passdbs));
	array_foreach_elem(&set->passdbs, passdb_name) {
		if (settings_get_filter(event, "passdb", passdb_name,
					&auth_passdb_setting_parser_info,
					0, &passdb_set, &error) < 0) {
			*error_r = t_strdup_printf("Failed to get passdb %s: %s",
						   passdb_name, error);
			return FALSE;
		}

		pool_add_external_ref(pool, passdb_set->pool);
		array_push_back(&set->parsed_passdbs, &passdb_set);
		settings_free(passdb_set);
	}
	return TRUE;
}

static bool
auth_settings_get_userdbs(struct auth_settings *set, pool_t pool,
			  struct event *event, const char **error_r)
{
	const struct auth_userdb_settings *userdb_set;
	const char *userdb_name, *error;

	if (!array_is_created(&set->userdbs))
		return TRUE;

	p_array_init(&set->parsed_userdbs, pool, array_count(&set->userdbs));
	array_foreach_elem(&set->userdbs, userdb_name) {
		if (settings_get_filter(event, "userdb", userdb_name,
					&auth_userdb_setting_parser_info,
					0, &userdb_set, &error) < 0) {
			*error_r = t_strdup_printf("Failed to get userdb %s: %s",
						   userdb_name, error);
			return FALSE;
		}

		pool_add_external_ref(pool, userdb_set->pool);
		array_push_back(&set->parsed_userdbs, &userdb_set);
		settings_free(userdb_set);
	}
	return TRUE;
}

static bool auth_settings_ext_check(struct event *event, void *_set,
				    pool_t pool, const char **error_r)
{
	struct auth_settings *set = _set;
	const char *p;

	if (set->debug_passwords)
		set->debug = TRUE;
	if (set->debug)
		set->verbose = TRUE;

	if (set->cache_size > 0 && set->cache_size < 1024) {
		/* probably a configuration error.
		   older versions used megabyte numbers */
		*error_r = t_strdup_printf("auth_cache_size value is too small "
					   "(%"PRIuUOFF_T" bytes)",
					   set->cache_size);
		return FALSE;
	}

	if (!auth_verify_verbose_password(set, error_r))
		return FALSE;

	if (*set->username_chars == '\0') {
		/* all chars are allowed */
		memset(set->username_chars_map, 1,
		       sizeof(set->username_chars_map));
	} else {
		for (p = set->username_chars; *p != '\0'; p++)
			set->username_chars_map[(int)(uint8_t)*p] = 1;
	}

	if (*set->username_translation != '\0') {
		p = set->username_translation;
		for (; *p != '\0' && p[1] != '\0'; p += 2)
			set->username_translation_map[(int)(uint8_t)*p] = p[1];
	}

	if (*set->policy_server_url != '\0') {
		if (*set->policy_hash_nonce == '\0') {

			*error_r = "auth_policy_hash_nonce must be set when policy server is used";
			return FALSE;
		}
		const struct hash_method *digest = hash_method_lookup(set->policy_hash_mech);
		if (digest == NULL) {
			*error_r = "invalid auth_policy_hash_mech given";
			return FALSE;
		}
		if (set->policy_hash_truncate > 0 && set->policy_hash_truncate >= digest->digest_size*8) {
			*error_r = t_strdup_printf("policy_hash_truncate is not smaller than digest size (%u >= %u)",
				set->policy_hash_truncate,
				digest->digest_size*8);
			return FALSE;
		}
	}

	if (!auth_settings_set_self_ips(set, pool, error_r))
		return FALSE;
	if (!auth_settings_get_passdbs(set, pool, event, error_r))
		return FALSE;
	if (!auth_settings_get_userdbs(set, pool, event, error_r))
		return FALSE;
	return TRUE;
}

static bool
auth_passdb_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			   const char **error_r ATTR_UNUSED)
{
	struct auth_passdb_settings *set = _set;

	if (*set->driver == '\0')
		set->driver = set->name;
	return TRUE;
}

static bool
auth_userdb_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			   const char **error_r ATTR_UNUSED)
{
	struct auth_userdb_settings *set = _set;

	if (*set->driver == '\0')
		set->driver = set->name;
	return TRUE;
}
/* </settings checks> */

const struct auth_settings *global_auth_settings;

void auth_settings_read(struct master_service_settings_output *output_r)
{
	struct master_service_settings_input input = {
		.no_protocol_filter = TRUE,
	};
	const char *error;

	settings_info_register(&auth_setting_parser_info);
	if (master_service_settings_read(master_service, &input,
					 output_r, &error) < 0)
		i_fatal("%s", error);
}

const struct auth_settings *auth_settings_get(const char *protocol)
{
	struct event *event = event_create(NULL);
	event_add_str(event, "protocol", protocol);
	const struct auth_settings *set =
		settings_get_or_fatal(event, &auth_setting_parser_info);
	event_unref(&event);
	return set;
}
