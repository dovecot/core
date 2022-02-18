/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash-method.h"
#include "settings-parser.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "service-settings.h"
#include "auth-settings.h"

#include <stddef.h>

static bool auth_settings_check(void *_set, pool_t pool, const char **error_r);
static bool auth_passdb_settings_check(void *_set, pool_t pool, const char **error_r);
static bool auth_userdb_settings_check(void *_set, pool_t pool, const char **error_r);

/* <settings checks> */
static struct file_listener_settings auth_unix_listeners_array[] = {
	{ "login/login", 0666, "", "" },
	{ "token-login/tokenlogin", 0666, "", "" },
	{ "auth-login", 0600, "$default_internal_user", "" },
	{ "auth-client", 0600, "$default_internal_user", "" },
	{ "auth-userdb", 0666, "$default_internal_user", "" },
	{ "auth-master", 0600, "", "" }
};
static struct file_listener_settings *auth_unix_listeners[] = {
	&auth_unix_listeners_array[0],
	&auth_unix_listeners_array[1],
	&auth_unix_listeners_array[2],
	&auth_unix_listeners_array[3],
	&auth_unix_listeners_array[4],
	&auth_unix_listeners_array[5]
};
static buffer_t auth_unix_listeners_buf = {
	{ { auth_unix_listeners, sizeof(auth_unix_listeners) } }
};
/* </settings checks> */

struct service_settings auth_service_settings = {
	.name = "auth",
	.protocol = "",
	.type = "",
	.executable = "auth",
	.user = "$default_internal_user",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &auth_unix_listeners_buf,
			      sizeof(auth_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT,

	.process_limit_1 = TRUE
};

/* <settings checks> */
static struct file_listener_settings auth_worker_unix_listeners_array[] = {
	{ "auth-worker", 0600, "$default_internal_user", "" }
};
static struct file_listener_settings *auth_worker_unix_listeners[] = {
	&auth_worker_unix_listeners_array[0]
};
static buffer_t auth_worker_unix_listeners_buf = {
	{ { auth_worker_unix_listeners, sizeof(auth_worker_unix_listeners) } }
};
/* </settings checks> */

struct service_settings auth_worker_service_settings = {
	.name = "auth-worker",
	.protocol = "",
	.type = "worker",
	.executable = "auth -w",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 30,
	.client_limit = 1,
	.service_count = 0,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &auth_worker_unix_listeners_buf,
			      sizeof(auth_worker_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_passdb_settings)

static const struct setting_define auth_passdb_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, driver),
	DEF(STR, args),
	DEF(STR, default_fields),
	DEF(STR, override_fields),
	DEF(STR, mechanisms),
	DEF(STR, username_filter),

	DEF(ENUM, skip),
	DEF(ENUM, result_success),
	DEF(ENUM, result_failure),
	DEF(ENUM, result_internalfail),

	DEF(BOOL, deny),
	DEF(BOOL, pass),
	DEF(BOOL, master),
	DEF(ENUM, auth_verbose),

	SETTING_DEFINE_LIST_END
};

static const struct auth_passdb_settings auth_passdb_default_settings = {
	.name = "",
	.driver = "",
	.args = "",
	.default_fields = "",
	.override_fields = "",
	.mechanisms = "",
	.username_filter = "",

	.skip = "never:authenticated:unauthenticated",
	.result_success = "return-ok:return:return-fail:continue:continue-ok:continue-fail",
	.result_failure = "continue:return:return-ok:return-fail:continue-ok:continue-fail",
	.result_internalfail = "continue:return:return-ok:return-fail:continue-ok:continue-fail",

	.deny = FALSE,
	.pass = FALSE,
	.master = FALSE,
	.auth_verbose = "default:yes:no"
};

const struct setting_parser_info auth_passdb_setting_parser_info = {
	.defines = auth_passdb_setting_defines,
	.defaults = &auth_passdb_default_settings,

	.type_offset = offsetof(struct auth_passdb_settings, name),
	.struct_size = sizeof(struct auth_passdb_settings),

	.parent_offset = SIZE_MAX,
	.parent = &auth_setting_parser_info,

	.check_func = auth_passdb_settings_check
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_userdb_settings)

static const struct setting_define auth_userdb_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, driver),
	DEF(STR, args),
	DEF(STR, default_fields),
	DEF(STR, override_fields),

	DEF(ENUM, skip),
	DEF(ENUM, result_success),
	DEF(ENUM, result_failure),
	DEF(ENUM, result_internalfail),

	DEF(ENUM, auth_verbose),

	SETTING_DEFINE_LIST_END
};

static const struct auth_userdb_settings auth_userdb_default_settings = {
	/* NOTE: when adding fields, update also auth.c:userdb_dummy_set */
	.name = "",
	.driver = "",
	.args = "",
	.default_fields = "",
	.override_fields = "",

	.skip = "never:found:notfound",
	.result_success = "return-ok:return:return-fail:continue:continue-ok:continue-fail",
	.result_failure = "continue:return:return-ok:return-fail:continue-ok:continue-fail",
	.result_internalfail = "continue:return:return-ok:return-fail:continue-ok:continue-fail",

	.auth_verbose = "default:yes:no"
};

const struct setting_parser_info auth_userdb_setting_parser_info = {
	.defines = auth_userdb_setting_defines,
	.defaults = &auth_userdb_default_settings,

	.type_offset = offsetof(struct auth_userdb_settings, name),
	.struct_size = sizeof(struct auth_userdb_settings),

	.parent_offset = SIZE_MAX,
	.parent = &auth_setting_parser_info,

	.check_func = auth_userdb_settings_check
};

/* we're kind of kludging here to avoid "auth_" prefix in the struct fields */
#undef DEF
#undef DEF_NOPREFIX
#undef DEFLIST
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("auth_"#name, name, struct auth_settings)
#define DEF_NOPREFIX(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct auth_settings)
#define DEFLIST(field, name, defines) \
	{ .type = SET_DEFLIST, .key = name, \
	  .offset = offsetof(struct auth_settings, field), \
	  .list_info = defines }

static const struct setting_define auth_setting_defines[] = {
	DEF(STR, mechanisms),
	DEF(STR, realms),
	DEF(STR, default_realm),
	DEF(SIZE, cache_size),
	DEF(TIME, cache_ttl),
	DEF(TIME, cache_negative_ttl),
	DEF(BOOL, cache_verify_password_with_worker),
	DEF(STR, username_chars),
	DEF(STR, username_translation),
	DEF(STR, username_format),
	DEF(STR, master_user_separator),
	DEF(STR, anonymous_username),
	DEF(STR, krb5_keytab),
	DEF(STR, gssapi_hostname),
	DEF(STR, winbind_helper_path),
	DEF(STR, proxy_self),
	DEF(TIME, failure_delay),

	DEF(STR, policy_server_url),
	DEF(STR, policy_server_api_header),
	DEF(UINT, policy_server_timeout_msecs),
	DEF(STR, policy_hash_mech),
	DEF(STR, policy_hash_nonce),
	DEF(STR, policy_request_attributes),
	DEF(BOOL, policy_reject_on_fail),
	DEF(BOOL, policy_check_before_auth),
	DEF(BOOL, policy_check_after_auth),
	DEF(BOOL, policy_report_after_auth),
	DEF(BOOL, policy_log_only),
	DEF(UINT, policy_hash_truncate),

	DEF(BOOL, verbose),
	DEF(BOOL, debug),
	DEF(BOOL, debug_passwords),
	DEF(BOOL, allow_weak_schemes),
	DEF(STR, verbose_passwords),
	DEF(BOOL, ssl_require_client_cert),
	DEF(BOOL, ssl_username_from_cert),
	DEF(BOOL, use_winbind),

	DEFLIST(passdbs, "passdb", &auth_passdb_setting_parser_info),
	DEFLIST(userdbs, "userdb", &auth_userdb_setting_parser_info),

	DEF_NOPREFIX(STR, base_dir),
	DEF_NOPREFIX(BOOL, verbose_proctitle),
	DEF_NOPREFIX(UINT, first_valid_uid),
	DEF_NOPREFIX(UINT, last_valid_uid),
	DEF_NOPREFIX(UINT, first_valid_gid),
	DEF_NOPREFIX(UINT, last_valid_gid),

	DEF_NOPREFIX(STR, ssl_client_ca_dir),
	DEF_NOPREFIX(STR, ssl_client_ca_file),

	SETTING_DEFINE_LIST_END
};

static const struct auth_settings auth_default_settings = {
	.mechanisms = "plain",
	.realms = "",
	.default_realm = "",
	.cache_size = 0,
	.cache_ttl = 60*60,
	.cache_negative_ttl = 60*60,
	.cache_verify_password_with_worker = FALSE,
	.username_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@",
	.username_translation = "",
	.username_format = "%Lu",
	.master_user_separator = "",
	.anonymous_username = "anonymous",
	.krb5_keytab = "",
	.gssapi_hostname = "",
	.winbind_helper_path = "/usr/bin/ntlm_auth",
	.proxy_self = "",
	.failure_delay = 2,

	.policy_server_url = "",
	.policy_server_api_header = "",
	.policy_server_timeout_msecs = 2000,
	.policy_hash_mech = "sha256",
	.policy_hash_nonce = "",
	.policy_request_attributes = "login=%{requested_username} pwhash=%{hashed_password} remote=%{rip} device_id=%{client_id} protocol=%s session_id=%{session}",
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
	.ssl_client_ca_dir = "",
	.ssl_client_ca_file = "",

	.use_winbind = FALSE,

	.passdbs = ARRAY_INIT,
	.userdbs = ARRAY_INIT,

	.base_dir = PKG_RUNDIR,
	.verbose_proctitle = FALSE,
	.first_valid_uid = 500,
	.last_valid_uid = 0,
	.first_valid_gid = 1,
	.last_valid_gid = 0,
};

const struct setting_parser_info auth_setting_parser_info = {
	.module_name = "auth",
	.defines = auth_setting_defines,
	.defaults = &auth_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct auth_settings),

	.parent_offset = SIZE_MAX,

	.check_func = auth_settings_check
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

static bool auth_settings_check(void *_set, pool_t pool,
				const char **error_r)
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
	set->realms_arr =
		(const char *const *)p_strsplit_spaces(pool, set->realms, " ");

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
	return TRUE;
}

static bool
auth_passdb_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			   const char **error_r)
{
	struct auth_passdb_settings *set = _set;

	if (set->driver == NULL || *set->driver == '\0') {
		*error_r = "passdb is missing driver";
		return FALSE;
	}
	if (set->pass && strcmp(set->result_success, "return-ok") != 0) {
		*error_r = "Obsolete pass=yes setting mixed with non-default result_success";
		return FALSE;
	}
	return TRUE;
}

static bool
auth_userdb_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			   const char **error_r)
{
	struct auth_userdb_settings *set = _set;

	if (set->driver == NULL || *set->driver == '\0') {
		*error_r = "userdb is missing driver";
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */

struct auth_settings *global_auth_settings;

struct auth_settings *
auth_settings_read(const char *service, pool_t pool,
		   struct master_service_settings_output *output_r)
{
	static const struct setting_parser_info *set_roots[] = {
		&auth_setting_parser_info,
		NULL
	};
	struct master_service_settings_input input;
	struct setting_parser_context *set_parser;
	const char *error;
	void **sets;

	i_zero(&input);
	input.roots = set_roots;
	input.module = "auth";
	input.service = service;
	if (master_service_settings_read(master_service, &input,
					 output_r, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	pool_ref(pool);
	set_parser = settings_parser_dup(master_service->set_parser, pool);
	if (!settings_parser_check(set_parser, pool, &error))
		i_unreached();

	sets = master_service_settings_parser_get_others(master_service,
							 set_parser);
	settings_parser_deinit(&set_parser);
	return sets[0];
}
