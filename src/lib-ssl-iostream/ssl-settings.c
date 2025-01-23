/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings.h"
#include "settings-parser.h"
#include "iostream-ssl.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct ssl_settings)

static bool
ssl_settings_check(void *_set, pool_t pool, const char **error_r);
static bool
ssl_server_settings_check(void *_set, pool_t pool, const char **error_r);

static const struct setting_define ssl_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "ssl_client", },
	{ .type = SET_FILTER_NAME, .key = "ssl_server", },

	DEF(FILE, ssl_client_ca_file),
	DEF(STR, ssl_client_ca_dir),
	DEF(FILE, ssl_client_cert_file),
	DEF(FILE, ssl_client_key_file),
	DEF(STR, ssl_client_key_password),

	DEF(STR, ssl_cipher_list),
	DEF(STR, ssl_cipher_suites),
	DEF(STR, ssl_curve_list),
	DEF(STR, ssl_min_protocol),
	DEF(STR, ssl_crypto_device),

	DEF(BOOL, ssl_client_require_valid_cert),
	DEF(STR, ssl_options), /* parsed as a string to set bools */

	SETTING_DEFINE_LIST_END
};

const struct ssl_settings ssl_default_settings = {
	.ssl_client_ca_file = "",
	.ssl_client_ca_dir = "",
	.ssl_client_cert_file = "",
	.ssl_client_key_file = "",
	.ssl_client_key_password = "",

	.ssl_cipher_list = "ALL:!kRSA:!SRP:!kDHd:!DSS:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!RC4:!ADH:!LOW@STRENGTH",
	.ssl_cipher_suites = "", /* Use TLS library provided value */
	.ssl_curve_list = "",
	.ssl_min_protocol = "TLSv1.2",
	.ssl_crypto_device = "",

	.ssl_client_require_valid_cert = TRUE,
	.ssl_options = "",
};

static const struct setting_keyvalue ssl_default_settings_keyvalue[] = {
	{ "ssl_client/ssl_cipher_list", "" },
	{ NULL, NULL }
};

const struct setting_parser_info ssl_setting_parser_info = {
	.name = "ssl",
	.defines = ssl_setting_defines,
	.defaults = &ssl_default_settings,
	.default_settings = ssl_default_settings_keyvalue,

	.pool_offset1 = 1 + offsetof(struct ssl_settings, pool),
	.struct_size = sizeof(struct ssl_settings),
	.check_func = ssl_settings_check
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct ssl_server_settings)

static const struct setting_define ssl_server_setting_defines[] = {
	DEF(ENUM, ssl),
	DEF(FILE, ssl_server_ca_file),
	DEF(FILE, ssl_server_cert_file),
	DEF(FILE, ssl_server_key_file),
	DEF(FILE, ssl_server_alt_cert_file),
	DEF(FILE, ssl_server_alt_key_file),
	DEF(STR, ssl_server_key_password),
	DEF(FILE, ssl_server_dh_file),
	DEF(STR, ssl_server_cert_username_field),
	DEF(ENUM, ssl_server_prefer_ciphers),

	DEF(BOOL, ssl_server_require_crl),
	DEF(BOOL, ssl_server_request_client_cert),

	SETTING_DEFINE_LIST_END
};

static const struct ssl_server_settings ssl_server_default_settings = {
	.ssl = "yes:no:required",
	.ssl_server_ca_file = "",
	.ssl_server_cert_file = "",
	.ssl_server_key_file = "",
	.ssl_server_alt_cert_file = "",
	.ssl_server_alt_key_file = "",
	.ssl_server_key_password = "",
	.ssl_server_dh_file = "",
	.ssl_server_cert_username_field = "commonName",
	.ssl_server_prefer_ciphers = "client:server",

	.ssl_server_require_crl = TRUE,
	.ssl_server_request_client_cert = FALSE,
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

	if (settings_get_config_binary() != SETTINGS_BINARY_OTHER) T_BEGIN {
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

	if (set->ssl_server_request_client_cert &&
	    *set->ssl_server_ca_file == '\0') {
		*error_r = "ssl_server_request_client_cert set, but ssl_server_ca_file not";
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */

int ssl_client_settings_get(struct event *event,
			    const struct ssl_settings **set_r,
			    const char **error_r)
{
	event = event_create(event);
	settings_event_add_filter_name(event, "ssl_client");
	int ret = settings_get(event, &ssl_setting_parser_info, 0,
			       set_r, error_r);
	event_unref(&event);
	return ret;
}

int ssl_server_settings_get(struct event *event,
			    const struct ssl_settings **set_r,
			    const struct ssl_server_settings **server_set_r,
			    const char **error_r)
{
	event = event_create(event);
	settings_event_add_filter_name(event, "ssl_server");
	int ret = settings_get(event, &ssl_setting_parser_info, 0,
			       set_r, error_r);
	if (ret == 0) {
		ret = settings_get(event, &ssl_server_setting_parser_info, 0,
				   server_set_r, error_r);
		if (ret < 0)
			settings_free(*set_r);
	}
	event_unref(&event);
	return ret;
}

static struct ssl_iostream_settings *
ssl_common_settings_to_iostream_set(const struct ssl_settings *ssl_set)
{
	struct ssl_iostream_settings *set;
	pool_t pool = pool_alloconly_create("ssl iostream settings", 512);
	set = p_new(pool, struct ssl_iostream_settings, 1);
	pool_add_external_ref(pool, ssl_set->pool);
	set->pool = pool;
	set->min_protocol = ssl_set->ssl_min_protocol;
	set->cipher_list = ssl_set->ssl_cipher_list;
	set->ciphersuites = ssl_set->ssl_cipher_suites;
	set->crypto_device = ssl_set->ssl_crypto_device;

	set->compression = ssl_set->parsed_opts.compression;
	set->tickets = ssl_set->parsed_opts.tickets;
	set->curve_list = ssl_set->ssl_curve_list;
	return set;
}

void ssl_client_settings_to_iostream_set(
	const struct ssl_settings *ssl_set,
	const struct ssl_iostream_settings **set_r)
{
	struct ssl_iostream_settings *set =
		ssl_common_settings_to_iostream_set(ssl_set);

	settings_file_get(ssl_set->ssl_client_ca_file,
			  set->pool, &set->ca);
	set->ca_dir = ssl_set->ssl_client_ca_dir;
	settings_file_get(ssl_set->ssl_client_cert_file,
			  set->pool, &set->cert.cert);
	settings_file_get(ssl_set->ssl_client_key_file,
			  set->pool, &set->cert.key);
	set->cert.key_password = ssl_set->ssl_client_key_password;
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
	pool_add_external_ref(set->pool, ssl_server_set->pool);

	settings_file_get(ssl_server_set->ssl_server_ca_file, set->pool, &set->ca);
	settings_file_get(ssl_server_set->ssl_server_cert_file,
			  set->pool, &set->cert.cert);
	settings_file_get(ssl_server_set->ssl_server_key_file,
			  set->pool, &set->cert.key);
	set->cert.key_password = ssl_server_set->ssl_server_key_password;
	if (ssl_server_set->ssl_server_alt_cert_file != NULL &&
	    *ssl_server_set->ssl_server_alt_cert_file != '\0') {
		settings_file_get(ssl_server_set->ssl_server_alt_cert_file,
				  set->pool, &set->alt_cert.cert);
		settings_file_get(ssl_server_set->ssl_server_alt_key_file,
				  set->pool, &set->alt_cert.key);
		set->alt_cert.key_password =
			ssl_server_set->ssl_server_key_password;
	}
	settings_file_get(ssl_server_set->ssl_server_dh_file,
			  set->pool, &set->dh);
	set->cert_username_field =
		ssl_server_set->ssl_server_cert_username_field;
	set->prefer_server_ciphers =
		strcmp(ssl_server_set->ssl_server_prefer_ciphers, "server") == 0;
	set->verify_remote_cert = ssl_server_set->ssl_server_request_client_cert;
	set->allow_invalid_cert = !set->verify_remote_cert;
	/* ssl_server_require_crl is used only for checking client-provided SSL
	   certificate's CRL. */
	set->skip_crl_check = !ssl_server_set->ssl_server_require_crl;
	*set_r = set;
}
