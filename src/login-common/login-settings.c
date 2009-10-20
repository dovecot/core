/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "login-settings.h"

#include <stddef.h>
#include <unistd.h>

static bool login_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct login_settings, name), NULL }

static struct setting_define login_setting_defines[] = {
	DEF(SET_STR, login_trusted_networks),
	DEF(SET_STR, login_greeting),
	DEF(SET_STR, login_log_format_elements),
	DEF(SET_STR, login_log_format),

	DEF(SET_ENUM, ssl),
	DEF(SET_STR, ssl_ca_file),
	DEF(SET_STR, ssl_cert),
	DEF(SET_STR, ssl_key),
	DEF(SET_STR, ssl_key_password),
	DEF(SET_STR, ssl_parameters_file),
	DEF(SET_STR, ssl_cipher_list),
	DEF(SET_STR, ssl_cert_username_field),
	DEF(SET_BOOL, ssl_verify_client_cert),
	DEF(SET_BOOL, ssl_require_client_cert),
	DEF(SET_BOOL, ssl_username_from_cert),
	DEF(SET_BOOL, verbose_ssl),

	DEF(SET_BOOL, disable_plaintext_auth),
	DEF(SET_BOOL, verbose_auth),
	DEF(SET_BOOL, auth_debug),
	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_UINT, mail_max_userip_connections),

	SETTING_DEFINE_LIST_END
};

static struct login_settings login_default_settings = {
	MEMBER(login_trusted_networks) "",
	MEMBER(login_greeting) PACKAGE_NAME" ready.",
	MEMBER(login_log_format_elements) "user=<%u> method=%m rip=%r lip=%l %c",
	MEMBER(login_log_format) "%$: %s",

	MEMBER(ssl) "yes:no:required",
	MEMBER(ssl_ca_file) "",
	MEMBER(ssl_cert) "",
	MEMBER(ssl_key) "",
	MEMBER(ssl_key_password) "",
	MEMBER(ssl_parameters_file) "ssl-parameters.dat",
	MEMBER(ssl_cipher_list) "ALL:!LOW:!SSLv2",
	MEMBER(ssl_cert_username_field) "commonName",
	MEMBER(ssl_verify_client_cert) FALSE,
	MEMBER(ssl_require_client_cert) FALSE,
	MEMBER(ssl_username_from_cert) FALSE,
	MEMBER(verbose_ssl) FALSE,

	MEMBER(disable_plaintext_auth) TRUE,
	MEMBER(verbose_auth) FALSE,
	MEMBER(auth_debug) FALSE,
	MEMBER(verbose_proctitle) FALSE,

	MEMBER(mail_max_userip_connections) 10
};

struct setting_parser_info login_setting_parser_info = {
	MEMBER(defines) login_setting_defines,
	MEMBER(defaults) &login_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct login_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) NULL,

	MEMBER(check_func) login_settings_check
};

const struct setting_parser_info *login_set_roots[] = {
	&login_setting_parser_info,
	NULL
};

/* <settings checks> */
static int ssl_settings_check(void *_set ATTR_UNUSED, const char **error_r)
{
	struct login_settings *set = _set;

#ifndef HAVE_SSL
	*error_r = t_strdup_printf("SSL support not compiled in but ssl=%s",
				   set->ssl);
	return FALSE;
#else
	if (*set->ssl_cert == '\0') {
		*error_r = "ssl enabled, but ssl_cert not set";
		return FALSE;
	}
	if (*set->ssl_key == '\0') {
		*error_r = "ssl enabled, but ssl_key not set";
		return FALSE;
	}
	if (set->ssl_verify_client_cert && *set->ssl_ca_file == '\0') {
		*error_r = "ssl_verify_client_cert set, but ssl_ca_file not";
		return FALSE;
	}

#ifndef CONFIG_BINARY
	if (*set->ssl_ca_file != '\0' && access(set->ssl_ca_file, R_OK) < 0) {
		*error_r = t_strdup_printf("ssl_ca_file: access(%s) failed: %m",
					   set->ssl_ca_file);
		return FALSE;
	}
#endif
	return TRUE;
#endif
}

static bool login_settings_check(void *_set, pool_t pool, const char **error_r)
{
	struct login_settings *set = _set;

	set->log_format_elements_split =
		p_strsplit(pool, set->login_log_format_elements, " ");

	if (set->ssl_require_client_cert || set->ssl_username_from_cert) {
		/* if we require valid cert, make sure we also ask for it */
		set->ssl_verify_client_cert = TRUE;
	}

	if (strcmp(set->ssl, "no") == 0) {
		/* disabled */
	} else if (strcmp(set->ssl, "yes") == 0) {
		if (!ssl_settings_check(set, error_r))
			return FALSE;
	} else if (strcmp(set->ssl, "required") == 0) {
		if (!ssl_settings_check(set, error_r))
			return FALSE;
		set->disable_plaintext_auth = TRUE;
	} else {
		*error_r = t_strdup_printf("Unknown ssl setting value: %s",
					   set->ssl);
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */

struct login_settings *
login_settings_read(struct master_service *service, pool_t pool,
		    const struct ip_addr *local_ip,
		    const struct ip_addr *remote_ip)
{
	struct master_service_settings_input input;
	const char *error;
	void **sets;
	struct login_settings *set;

	memset(&input, 0, sizeof(input));
	input.roots = login_set_roots;
	input.module = "login";
	input.service = login_protocol;

	if (local_ip != NULL)
		input.local_ip = *local_ip;
	if (remote_ip != NULL)
		input.remote_ip = *remote_ip;

	/* this function always clears the previous settings pool. since we're
	   doing per-connection lookups, we always need to duplicate the
	   settings using another pool. */
	if (master_service_settings_read(service, &input, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	sets = master_service_settings_get_others(service);
	set = settings_dup(&login_setting_parser_info, sets[0], pool);
	if (!login_settings_check(set, pool, &error))
		i_fatal("login_settings_check() failed: %s", error);
	return set;
}
