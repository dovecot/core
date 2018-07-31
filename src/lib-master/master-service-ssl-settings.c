/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "master-service-private.h"
#include "master-service-ssl-settings.h"
#include "iostream-ssl.h"

#include <stddef.h>

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
	DEF(SET_STR, ssl_client_ca_file),
	DEF(SET_STR, ssl_client_ca_dir),
	DEF(SET_STR, ssl_client_cert),
	DEF(SET_STR, ssl_client_key),
	DEF(SET_STR, ssl_dh),
	DEF(SET_STR, ssl_cipher_list),
	DEF(SET_STR, ssl_curve_list),
	DEF(SET_STR, ssl_min_protocol),
	DEF(SET_STR, ssl_cert_username_field),
	DEF(SET_STR, ssl_crypto_device),
	DEF(SET_BOOL, ssl_verify_client_cert),
	DEF(SET_BOOL, ssl_require_crl),
	DEF(SET_BOOL, verbose_ssl),
	DEF(SET_BOOL, ssl_prefer_server_ciphers),
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
	.ssl_client_ca_file = "",
	.ssl_client_ca_dir = "",
	.ssl_client_cert = "",
	.ssl_client_key = "",
	.ssl_dh = "",
	.ssl_cipher_list = "ALL:!kRSA:!SRP:!kDHd:!DSS:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!RC4:!ADH:!LOW@STRENGTH",
	.ssl_curve_list = "",
	.ssl_min_protocol = "TLSv1",
	.ssl_cert_username_field = "commonName",
	.ssl_crypto_device = "",
	.ssl_verify_client_cert = FALSE,
	.ssl_require_crl = TRUE,
	.verbose_ssl = FALSE,
	.ssl_prefer_server_ciphers = FALSE,
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
#ifdef CONFIG_BINARY
	if (*set->ssl_cert == '\0') {
		*error_r = "ssl enabled, but ssl_cert not set";
		return FALSE;
	}
	if (*set->ssl_key == '\0') {
		*error_r = "ssl enabled, but ssl_key not set";
		return FALSE;
	}
	if (*set->ssl_dh == '\0') {
		*error_r = "ssl enabled, but ssl_dh not set";
		return FALSE;
	}
#endif
	if (set->ssl_verify_client_cert && *set->ssl_ca == '\0') {
		*error_r = "ssl_verify_client_cert set, but ssl_ca not";
		return FALSE;
	}

	/* Now explode the ssl_options string into individual flags */
	/* First set them all to defaults */
	set->parsed_opts.compression = FALSE;
	set->parsed_opts.tickets = TRUE;

	/* Then modify anything specified in the string */
	const char **opts = t_strsplit_spaces(set->ssl_options, ", ");
	const char *opt;
	while ((opt = *opts++) != NULL) {
		if (strcasecmp(opt, "compression") == 0) {
			set->parsed_opts.compression = TRUE;
		} else if (strcasecmp(opt, "no_compression") == 0) {
#ifdef CONFIG_BINARY
			i_warning("DEPRECATED: no_compression is default, "
				  "so it is redundant in ssl_options");
#endif
		} else if (strcasecmp(opt, "no_ticket") == 0) {
			set->parsed_opts.tickets = FALSE;
		} else {
			*error_r = t_strdup_printf("ssl_options: unknown flag: '%s'",
						   opt);
			return FALSE;
		}
	}

#ifndef HAVE_SSL_CTX_SET1_CURVES_LIST
	if (*set->ssl_curve_list != '\0') {
		*error_r = "ssl_curve_list is set, but the linked openssl "
			   "version does not support it";
		return FALSE;
	}
#endif

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

void master_service_ssl_settings_to_iostream_set(
	const struct master_service_ssl_settings *ssl_set, pool_t pool,
	enum master_service_ssl_settings_type type,
	struct ssl_iostream_settings *set_r)
{
	i_zero(set_r);
	set_r->min_protocol = p_strdup(pool, ssl_set->ssl_min_protocol);
	set_r->cipher_list = p_strdup(pool, ssl_set->ssl_cipher_list);
	/* NOTE: It's a bit questionable whether ssl_ca should be used for
	   clients. But at least for now it's needed for login-proxy. */
	set_r->ca = p_strdup(pool, ssl_set->ssl_ca);

	switch (type) {
	case MASTER_SERVICE_SSL_SETTINGS_TYPE_SERVER:
		set_r->cert.cert = p_strdup(pool, ssl_set->ssl_cert);
		set_r->cert.key = p_strdup(pool, ssl_set->ssl_key);
		set_r->cert.key_password = p_strdup(pool, ssl_set->ssl_key_password);
		if (ssl_set->ssl_alt_cert != NULL && *ssl_set->ssl_alt_cert != '\0') {
			set_r->alt_cert.cert = p_strdup(pool, ssl_set->ssl_alt_cert);
			set_r->alt_cert.key = p_strdup(pool, ssl_set->ssl_alt_key);
			set_r->alt_cert.key_password = p_strdup(pool, ssl_set->ssl_key_password);
		}
		set_r->verify_remote_cert = ssl_set->ssl_verify_client_cert;
		set_r->allow_invalid_cert = !set_r->verify_remote_cert;
		break;
	case MASTER_SERVICE_SSL_SETTINGS_TYPE_CLIENT:
		set_r->ca_file = p_strdup(pool, ssl_set->ssl_client_ca_file);
		set_r->ca_dir = p_strdup(pool, ssl_set->ssl_client_ca_dir);
		set_r->cert.cert = p_strdup_empty(pool, ssl_set->ssl_client_cert);
		set_r->cert.key = p_strdup_empty(pool, ssl_set->ssl_client_key);
		set_r->verify_remote_cert = TRUE;
		break;
	}

	set_r->dh = p_strdup(pool, ssl_set->ssl_dh);
	set_r->crypto_device = p_strdup(pool, ssl_set->ssl_crypto_device);
	set_r->cert_username_field = p_strdup(pool, ssl_set->ssl_cert_username_field);

	set_r->verbose = ssl_set->verbose_ssl;
	set_r->verbose_invalid_cert = ssl_set->verbose_ssl;
	set_r->skip_crl_check = !ssl_set->ssl_require_crl;
	set_r->prefer_server_ciphers = ssl_set->ssl_prefer_server_ciphers;
	set_r->compression = ssl_set->parsed_opts.compression;
	set_r->tickets = ssl_set->parsed_opts.tickets;
	set_r->curve_list = p_strdup(pool, ssl_set->ssl_curve_list);
}
