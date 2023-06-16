/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "master-service-private.h"
#include "master-service-ssl-settings.h"
#include "iostream-ssl.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct ssl_settings)

static bool
ssl_settings_check(void *_set, pool_t pool, const char **error_r);
static bool
ssl_server_settings_check(void *_set, pool_t pool, const char **error_r);

static const struct setting_define ssl_setting_defines[] = {
	DEF(STR, ssl_client_ca),
	DEF(STR, ssl_client_ca_file),
	DEF(STR, ssl_client_ca_dir),
	DEF(STR, ssl_client_cert),
	DEF(STR, ssl_client_key),

	DEF(STR, ssl_cipher_list),
	DEF(STR, ssl_cipher_suites),
	DEF(STR, ssl_curve_list),
	DEF(STR, ssl_min_protocol),
	DEF(STR, ssl_crypto_device),

	DEF(BOOL, ssl_client_require_valid_cert),
	DEF(STR, ssl_options), /* parsed as a string to set bools */

	SETTING_DEFINE_LIST_END
};

static const struct ssl_settings ssl_default_settings = {
	.ssl_client_ca = "",
	.ssl_client_ca_file = "",
	.ssl_client_ca_dir = "",
	.ssl_client_cert = "",
	.ssl_client_key = "",

	.ssl_cipher_list = "ALL:!kRSA:!SRP:!kDHd:!DSS:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!RC4:!ADH:!LOW@STRENGTH",
	.ssl_cipher_suites = "", /* Use TLS library provided value */
	.ssl_curve_list = "",
	.ssl_min_protocol = "TLSv1.2",
	.ssl_crypto_device = "",

	.ssl_client_require_valid_cert = TRUE,
	.ssl_options = "",
};

const struct setting_parser_info ssl_setting_parser_info = {
	.name = "ssl",
	.defines = ssl_setting_defines,
	.defaults = &ssl_default_settings,

	.pool_offset1 = 1 + offsetof(struct ssl_settings, pool),
	.struct_size = sizeof(struct ssl_settings),
	.check_func = ssl_settings_check
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct ssl_server_settings)

static const struct setting_define ssl_server_setting_defines[] = {
	DEF(ENUM, ssl),
	DEF(STR, ssl_ca),
	DEF(STR, ssl_cert),
	DEF(STR, ssl_key),
	DEF(STR, ssl_alt_cert),
	DEF(STR, ssl_alt_key),
	DEF(STR, ssl_key_password),
	DEF(STR, ssl_dh),
	DEF(STR, ssl_cert_username_field),

	DEF(BOOL, ssl_require_crl),
	DEF(BOOL, ssl_prefer_server_ciphers),
	DEF(BOOL, ssl_request_client_cert),

	SETTING_DEFINE_LIST_END
};

static const struct ssl_server_settings ssl_server_default_settings = {
	.ssl = "yes:no:required",
	.ssl_ca = "",
	.ssl_cert = "",
	.ssl_key = "",
	.ssl_alt_cert = "",
	.ssl_alt_key = "",
	.ssl_key_password = "",
	.ssl_dh = "",
	.ssl_cert_username_field = "commonName",

	.ssl_require_crl = TRUE,
	.ssl_prefer_server_ciphers = FALSE,
	.ssl_request_client_cert = FALSE,
};

const struct setting_parser_info ssl_server_setting_parser_info = {
	.name = "ssl_server",

	.defines = ssl_server_setting_defines,
	.defaults = &ssl_server_default_settings,

	.pool_offset1 = 1 + offsetof(struct ssl_server_settings, pool),
	.struct_size = sizeof(struct ssl_server_settings),
	.check_func = ssl_server_settings_check,
};

/* <settings checks> */
static bool
ssl_settings_check(void *_set, pool_t pool ATTR_UNUSED,
		   const char **error_r)
{
	struct ssl_settings *set = _set;

	if (is_config_binary()) T_BEGIN {
		const char *proto = t_str_ucase(set->ssl_min_protocol);
		if (strstr(proto, "ANY") != NULL)
			i_warning("ssl_min_protocol=ANY is used - This is "
				  "insecure and intended only for testing");
	} T_END;

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
		} else if (strcasecmp(opt, "no_ticket") == 0) {
			set->parsed_opts.tickets = FALSE;
		} else {
			*error_r = t_strdup_printf("ssl_options: unknown flag: '%s'",
						   opt);
			return FALSE;
		}
	}

	return TRUE;
}

static bool
ssl_server_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			  const char **error_r)
{
	struct ssl_server_settings *set = _set;

	if (strcmp(set->ssl, "no") == 0) {
		/* disabled */
		return TRUE;
	}

	if (set->ssl_request_client_cert && *set->ssl_ca == '\0') {
		*error_r = "ssl_request_client_cert set, but ssl_ca not";
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */

static struct ssl_iostream_settings *
ssl_common_settings_to_iostream_set(const struct ssl_settings *ssl_set)
{
	struct ssl_iostream_settings *set;
	pool_t pool = pool_alloconly_create("ssl iostream settings", 256);
	set = p_new(pool, struct ssl_iostream_settings, 1);
	set->pool = pool;
	set->min_protocol = p_strdup(pool, ssl_set->ssl_min_protocol);
	set->cipher_list = p_strdup(pool, ssl_set->ssl_cipher_list);
	/* leave NULL if empty - let library decide */
	set->ciphersuites = p_strdup_empty(pool, ssl_set->ssl_cipher_suites);

	set->crypto_device = p_strdup(pool, ssl_set->ssl_crypto_device);

	set->compression = ssl_set->parsed_opts.compression;
	set->tickets = ssl_set->parsed_opts.tickets;
	set->curve_list = p_strdup(pool, ssl_set->ssl_curve_list);
	return set;
}

void ssl_client_settings_to_iostream_set(
	const struct ssl_settings *ssl_set,
	const struct ssl_iostream_settings **set_r)
{
	struct ssl_iostream_settings *set =
		ssl_common_settings_to_iostream_set(ssl_set);
	pool_t pool = set->pool;

	set->ca = p_strdup_empty(pool, ssl_set->ssl_client_ca);
	set->ca_file = p_strdup_empty(pool, ssl_set->ssl_client_ca_file);
	set->ca_dir = p_strdup_empty(pool, ssl_set->ssl_client_ca_dir);
	set->cert.cert = p_strdup_empty(pool, ssl_set->ssl_client_cert);
	set->cert.key = p_strdup_empty(pool, ssl_set->ssl_client_key);
	set->verify_remote_cert = ssl_set->ssl_client_require_valid_cert;
	set->allow_invalid_cert = !set->verify_remote_cert;
	/* client-side CRL checking not supported currently */
	set->skip_crl_check = TRUE;
	*set_r = set;
}

void ssl_server_settings_to_iostream_set(
	const struct ssl_settings *ssl_set,
	const struct ssl_server_settings *ssl_server_set,
	const struct ssl_iostream_settings **set_r)
{
	struct ssl_iostream_settings *set =
		ssl_common_settings_to_iostream_set(ssl_set);
	pool_t pool = set->pool;

	set->ca = p_strdup_empty(pool, ssl_server_set->ssl_ca);
	set->cert.cert = p_strdup(pool, ssl_server_set->ssl_cert);
	set->cert.key = p_strdup(pool, ssl_server_set->ssl_key);
	set->cert.key_password = p_strdup(pool, ssl_server_set->ssl_key_password);
	if (ssl_server_set->ssl_alt_cert != NULL &&
	    *ssl_server_set->ssl_alt_cert != '\0') {
		set->alt_cert.cert = p_strdup(pool, ssl_server_set->ssl_alt_cert);
		set->alt_cert.key = p_strdup(pool, ssl_server_set->ssl_alt_key);
		set->alt_cert.key_password = p_strdup(pool, ssl_server_set->ssl_key_password);
	}
	set->dh = p_strdup(pool, ssl_server_set->ssl_dh);
	set->cert_username_field =
		p_strdup(pool, ssl_server_set->ssl_cert_username_field);
	set->prefer_server_ciphers = ssl_server_set->ssl_prefer_server_ciphers;
	set->verify_remote_cert = ssl_server_set->ssl_request_client_cert;
	set->allow_invalid_cert = !set->verify_remote_cert;
	/* ssl_require_crl is used only for checking client-provided SSL
	   certificate's CRL. */
	set->skip_crl_check = !ssl_server_set->ssl_require_crl;
	*set_r = set;
}
