/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "master-service-private.h"
#include "master-service-ssl-settings.h"

#include <stddef.h>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#endif

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct master_service_ssl_settings, name), NULL }

static bool
master_service_ssl_settings_check(void *_set, pool_t pool, const char **error_r);

static const struct setting_define master_service_ssl_setting_defines[] = {
	DEF(SET_ENUM, ssl),
	DEF(SET_STR, ssl_ca),
	DEF(SET_STR, ssl_cert),
	DEF(SET_STR, ssl_key),
	DEF(SET_STR, ssl_alt_cert),
	DEF(SET_STR, ssl_alt_key),
	DEF(SET_STR, ssl_key_password),
	DEF(SET_STR, ssl_cipher_list),
	DEF(SET_STR, ssl_protocols),
	DEF(SET_STR, ssl_cert_username_field),
	DEF(SET_STR, ssl_crypto_device),
	DEF(SET_STR, ssl_cert_md_algorithm),
	DEF(SET_UINT, ssl_verify_depth),
	DEF(SET_BOOL, ssl_verify_client_cert),
	DEF(SET_BOOL, ssl_require_crl),
	DEF(SET_BOOL, verbose_ssl),
	DEF(SET_BOOL, ssl_prefer_server_ciphers),
	DEF(SET_BOOL, ssl_cert_info),
	DEF(SET_BOOL, ssl_cert_debug),
	DEF(SET_STR, ssl_options), /* parsed as a string to set bools */

	SETTING_DEFINE_LIST_END
};

static const struct master_service_ssl_settings master_service_ssl_default_settings = {
#ifdef HAVE_SSL
	.ssl = "yes:no:required",
#else
	.ssl = "no:yes:required",
#endif
	.ssl_ca = "",
	.ssl_cert = "",
	.ssl_key = "",
	.ssl_alt_cert = "",
	.ssl_alt_key = "",
	.ssl_key_password = "",
	.ssl_cipher_list = "ALL:!LOW:!SSLv2:!EXP:!aNULL",
#ifdef SSL_TXT_SSLV2
	.ssl_protocols = "!SSLv2 !SSLv3",
#else
	.ssl_protocols = "!SSLv3",
#endif
	.ssl_cert_username_field = "commonName",
	.ssl_crypto_device = "",
	.ssl_cert_md_algorithm = "sha1",
	.ssl_verify_depth = 9,
	.ssl_verify_client_cert = FALSE,
	.ssl_require_crl = TRUE,
	.verbose_ssl = FALSE,
	.ssl_prefer_server_ciphers = FALSE,
	.ssl_cert_info = FALSE,
	.ssl_cert_debug = FALSE,
	.ssl_options = "",
};

const struct setting_parser_info master_service_ssl_setting_parser_info = {
	.module_name = "ssl",
	.defines = master_service_ssl_setting_defines,
	.defaults = &master_service_ssl_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct master_service_ssl_settings),

	.parent_offset = (size_t)-1,
	.check_func = master_service_ssl_settings_check
};

/* <settings checks> */
static bool
master_service_ssl_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				  const char **error_r)
{
	struct master_service_ssl_settings *set = _set;

	if (strcmp(set->ssl, "no") == 0) {
		/* disabled */
		return TRUE;
	}
#ifndef HAVE_SSL
	*error_r = t_strdup_printf("SSL support not compiled in but ssl=%s",
				   set->ssl);
	return FALSE;
#else
	/* we get called from many different tools, possibly with -O parameter,
	   and few of those tools care about SSL settings. so don't check
	   ssl_cert/ssl_key/etc validity here except in doveconf, because it
	   usually is just an extra annoyance. */
#ifdef CONFIG
	if (*set->ssl_cert == '\0') {
		*error_r = "ssl enabled, but ssl_cert not set";
		return FALSE;
	}
	if (*set->ssl_key == '\0') {
		*error_r = "ssl enabled, but ssl_key not set";
		return FALSE;
	}
#endif
	if (set->ssl_verify_client_cert && *set->ssl_ca == '\0') {
		*error_r = "ssl_verify_client_cert set, but ssl_ca not";
		return FALSE;
	}

	/* Now explode the ssl_options string into individual flags */
	/* First set them all to defaults */
	set->parsed_opts.compression = TRUE;
	set->parsed_opts.tickets = TRUE;

	/* Then modify anything specified in the string */
	const char **opts = t_strsplit_spaces(set->ssl_options, ", ");
	const char *opt;
	while ((opt = *opts++) != NULL) {
		if (strcasecmp(opt, "no_compression") == 0) {
			set->parsed_opts.compression = FALSE;
		} else if (strcasecmp(opt, "no_ticket") == 0) {
			set->parsed_opts.tickets = FALSE;
		} else {
			*error_r = t_strdup_printf("ssl_options: unknown flag: '%s'",
						   opt);
			return FALSE;
		}
	}

	return TRUE;
#endif
}
/* </settings checks> */

const struct master_service_ssl_settings *
master_service_ssl_settings_get(struct master_service *service)
{
	void **sets;

	sets = settings_parser_get_list(service->set_parser);
	return sets[1];
}
