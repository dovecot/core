/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "login-settings.h"

#include <stddef.h>
#include <unistd.h>

static bool login_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct login_settings, name), NULL }

static struct setting_define login_setting_defines[] = {
	DEF(SET_STR, login_dir),
	DEF(SET_BOOL, login_chroot),
	DEF(SET_STR, login_trusted_networks),
	DEF(SET_STR, login_greeting),
	DEF(SET_STR, login_log_format_elements),
	DEF(SET_STR, login_log_format),

	DEF(SET_BOOL, login_process_per_connection),
	DEF(SET_STR, capability_string),

	DEF(SET_ENUM, ssl),
	DEF(SET_STR, ssl_ca_file),
	DEF(SET_STR, ssl_cert_file),
	DEF(SET_STR, ssl_key_file),
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

	DEF(SET_UINT, login_max_connections),

	SETTING_DEFINE_LIST_END
};

static struct login_settings login_default_settings = {
	MEMBER(login_dir) "login",
	MEMBER(login_chroot) TRUE,
	MEMBER(login_trusted_networks) "",
	MEMBER(login_greeting) PACKAGE" ready.",
	MEMBER(login_log_format_elements) "user=<%u> method=%m rip=%r lip=%l %c",
	MEMBER(login_log_format) "%$: %s",

	MEMBER(login_process_per_connection) TRUE,
	MEMBER(capability_string) NULL,

	MEMBER(ssl) "yes:no:required",
	MEMBER(ssl_ca_file) "",
	MEMBER(ssl_cert_file) SSLDIR"/certs/dovecot.pem",
	MEMBER(ssl_key_file) SSLDIR"/private/dovecot.pem",
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

	MEMBER(login_max_connections) 256
};

struct setting_parser_info login_setting_parser_info = {
	MEMBER(defines) login_setting_defines,
	MEMBER(defaults) &login_default_settings,

	MEMBER(parent) NULL,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct login_settings),
	MEMBER(check_func) login_settings_check
};

static pool_t settings_pool = NULL;

/* <settings checks> */
static int ssl_settings_check(void *_set ATTR_UNUSED, const char **error_r)
{
	struct login_settings *set = _set;

#ifndef HAVE_SSL
	*error_r = t_strdup_printf("SSL support not compiled in but ssl=%s",
				   set->ssl);
	return FALSE;
#else
	if (*set->ssl_cert_file == '\0') {
		*error_r = "ssl_cert_file not set";
		return FALSE;
	}
	if (*set->ssl_key_file == '\0') {
		*error_r = "ssl_key_file not set";
		return FALSE;
	}
	if (set->ssl_verify_client_cert && *set->ssl_ca_file == '\0') {
		*error_r = "ssl_verify_client_cert set, but ssl_ca_file not";
		return FALSE;
	}

#ifndef CONFIG_BINARY
	if (access(set->ssl_cert_file, R_OK) < 0) {
		*error_r = t_strdup_printf("ssl_cert_file: access(%s) failed: %m",
					   set->ssl_cert_file);
		return FALSE;
	}
	if (access(set->ssl_key_file, R_OK) < 0) {
		*error_r = t_strdup_printf("ssl_key_file: access(%s) failed: %m",
					   set->ssl_key_file);
		return FALSE;
	}
	if (*set->ssl_ca_file != '\0' && access(set->ssl_ca_file, R_OK) < 0) {
		*error_r = t_strdup_printf("ssl_ca_file: access(%s) failed: %m",
					   set->ssl_ca_file);
		return FALSE;
	}
#endif
	return TRUE;
#endif
}

static bool login_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				 const char **error_r)
{
	struct login_settings *set = _set;

	set->log_format_elements_split =
		t_strsplit(set->login_log_format_elements, " ");

	if (set->ssl_require_client_cert || set->ssl_username_from_cert) {
		/* if we require valid cert, make sure we also ask for it */
		set->ssl_verify_client_cert = TRUE;
	}
	if (set->login_max_connections < 1) {
		*error_r = "login_max_connections must be at least 1";
		return FALSE;
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

struct login_settings *login_settings_read(void)
{
	struct setting_parser_context *parser;
        struct login_settings *set;
	const char *error;

	if (settings_pool == NULL)
		settings_pool = pool_alloconly_create("settings pool", 512);
	else
		p_clear(settings_pool);

	parser = settings_parser_init(settings_pool,
				      &login_setting_parser_info,
				      SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);

	if (settings_parse_environ(parser) < 0) {
		i_fatal("Error reading configuration: %s",
			settings_parser_get_error(parser));
	}

	if (settings_parser_check(parser, settings_pool, &error) < 0)
		i_fatal("Invalid settings: %s", error);

	set = settings_parser_get(parser);
	settings_parser_deinit(&parser);
	return set;
}
