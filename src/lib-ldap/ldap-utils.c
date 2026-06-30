/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ldap-utils.h"
#include "ssl-settings.h"
#include "iostream-ssl.h"
#include "settings-parser.h"

#ifdef LDAP_OPT_X_TLS

static const struct {
	const char *name;
	int opt;
} protocol_versions[] = {
	{ "ANY", LDAP_OPT_X_TLS_PROTOCOL_SSL3 },
	{ "TLSv1", LDAP_OPT_X_TLS_PROTOCOL_TLS1_0 },
	{ "TLSv1.1", LDAP_OPT_X_TLS_PROTOCOL_TLS1_1 },
	{ "TLSv1.2", LDAP_OPT_X_TLS_PROTOCOL_TLS1_2 },
#ifndef LDAP_OPT_X_TLS_PROTOCOL_TLS1_3
	{ "LATEST", LDAP_OPT_X_TLS_PROTOCOL_TLS1_2 }
#else
	{ "TLSv1.3", LDAP_OPT_X_TLS_PROTOCOL_TLS1_3 },
	{ "LATEST", LDAP_OPT_X_TLS_PROTOCOL_TLS1_3 }
#endif
};

static int ldap_min_protocol_to_option(const char *min_protocol, int *opt_r)
{
	unsigned int i = 0;
	for (; i < N_ELEMENTS(protocol_versions); i++) {
		if (strcasecmp(protocol_versions[i].name, min_protocol) == 0) {
			*opt_r = protocol_versions[i].opt;
			return 0;
		}
	}
	return -1;
}

#endif

int ldap_set_opt(LDAP *ld, int opt, const void *value,
		 const char *optname, const char *value_str,
		 const char **error_r)
{
	int ret;

	ret = ldap_set_option(ld, opt, value);
	if (ret != LDAP_SUCCESS) {
		*error_r = t_strdup_printf("Can't set option %s to %s: %s",
			optname, value_str, ldap_err2string(ret));
		return -1;
	}
	return 0;
}

int ldap_set_opt_str(LDAP *ld, int opt, const char *value,
		     const char *optname, const char **error_r)
{
	if (*value != '\0')
		return ldap_set_opt(ld, opt, value, optname, value, error_r);

	/* Copy it from global context. This allows getting defaults from
	   ldap.conf */
	char *global_value;
	if (ldap_get_option(NULL, opt, &global_value) != LDAP_SUCCESS)
		i_unreached();
	if (global_value == NULL)
		return 0;

	int ret = 0;
	if (global_value[0] != '\0') {
		ret = ldap_set_opt(ld, opt, global_value, optname,
				   global_value, error_r);
	}
	free(global_value);
	return ret;
}

#ifndef LDAP_OPT_X_TLS
int ldap_set_tls_options(LDAP *ld ATTR_UNUSED, bool starttls ATTR_UNUSED,
			 const char *uris ATTR_UNUSED,
			 const struct ssl_settings *ssl_set ATTR_UNUSED,
			 const char **error_r ATTR_UNUSED)
{
	return 0;
}
#else
static bool ldap_tls_opt_is_set(LDAP *ld, int opt)
{
	char *value;
	if (ldap_get_option(ld, opt, &value) != LDAP_SUCCESS || value == NULL)
		return FALSE;
	bool is_set = value[0] != '\0';
	free(value);
	return is_set;
}

/* Returns TRUE if the handle already has a CA file or dir configured, either
   from Dovecot settings or inherited from ldap.conf. */
static bool ldap_tls_has_ca(LDAP *ld)
{
	return ldap_tls_opt_is_set(ld, LDAP_OPT_X_TLS_CACERTFILE) ||
	       ldap_tls_opt_is_set(ld, LDAP_OPT_X_TLS_CACERTDIR);
}

int ldap_set_tls_options(LDAP *ld, bool starttls, const char *uris,
			 const struct ssl_settings *ssl_set,
			 const char **error_r)
{
	if (!starttls && strstr(uris, "ldaps:") == NULL)
		return 0;

	struct settings_file key_file, cert_file, ca_file;
	settings_file_get(ssl_set->ssl_client_key_file,
			  unsafe_data_stack_pool, &key_file);
	settings_file_get(ssl_set->ssl_client_cert_file,
			  unsafe_data_stack_pool, &cert_file);
	settings_file_get(ssl_set->ssl_client_ca_file,
			  unsafe_data_stack_pool, &ca_file);

	ldap_init_defaults();

	/* If either ssl_client_ca_file or ssl_client_ca_dir is set,
	   the defaults for neither is read from ldap.conf. This avoids
	   confusion of using both settings, which can't be easily even
	   disabled on Dovecot side. */
	bool have_ca_settings = ca_file.path[0] != '\0' ||
		ssl_set->ssl_client_ca_dir[0] != '\0';
	if (ca_file.path[0] != '\0' || !have_ca_settings) {
		if (ldap_set_opt_str(ld, LDAP_OPT_X_TLS_CACERTFILE,
				     ca_file.path, "ssl_client_ca_file", error_r) < 0)
			return -1;
	}
	if (ssl_set->ssl_client_ca_dir[0] != '\0' || !have_ca_settings) {
		if (ldap_set_opt_str(ld, LDAP_OPT_X_TLS_CACERTDIR,
				     ssl_set->ssl_client_ca_dir,
				     "ssl_client_ca_dir", error_r) < 0)
			return -1;
	}
	/* If neither Dovecot nor ldap.conf provides a CA, fall back to the
	   OpenSSL system default CA paths. OpenLDAP built against GnuTLS does
	   not load the system trust store on its own (unlike its OpenSSL
	   backend), so without this the handshake has no trust anchors. This
	   mirrors lib-ssl-iostream's SSL_CTX_set_default_verify_paths(). */
	if (!have_ca_settings && !ldap_tls_has_ca(ld)) {
		const char *default_ca_file, *default_ca_dir;
		if (ssl_iostream_get_default_ca_paths(&default_ca_file,
						      &default_ca_dir,
						      error_r) < 0)
			return -1;
		if (default_ca_file != NULL &&
		    ldap_set_opt_str(ld, LDAP_OPT_X_TLS_CACERTFILE,
				     default_ca_file, "ssl_client_ca_file",
				     error_r) < 0)
			return -1;
		if (default_ca_dir != NULL &&
		    ldap_set_opt_str(ld, LDAP_OPT_X_TLS_CACERTDIR,
				     default_ca_dir, "ssl_client_ca_dir",
				     error_r) < 0)
			return -1;
	}
	if (ldap_set_opt_str(ld, LDAP_OPT_X_TLS_CERTFILE, cert_file.path,
			     "ssl_client_cert_file", error_r) < 0)
		return -1;
	if (ldap_set_opt_str(ld, LDAP_OPT_X_TLS_KEYFILE, key_file.path,
			     "ssl_client_key_file", error_r) < 0)
		return -1;
	if (ldap_set_opt_str(ld, LDAP_OPT_X_TLS_CIPHER_SUITE,
			     ssl_set->ssl_cipher_list,
			     "ssl_cipher_list", error_r) < 0)
		return -1;
	if (ldap_set_opt_str(ld, LDAP_OPT_X_TLS_ECNAME,
			     ssl_set->ssl_curve_list,
			     "ssl_curve_list", error_r) < 0)
		return -1;

	bool requires = ssl_set->ssl_client_require_valid_cert;
	int opt = requires ? LDAP_OPT_X_TLS_HARD : LDAP_OPT_X_TLS_ALLOW;
	if (ldap_set_opt(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &opt,
			 "ssl_client_require_valid_cert",
			 requires ? "yes" : "no", error_r) < 0)
		return -1;

	if (ldap_min_protocol_to_option(ssl_set->ssl_min_protocol, &opt) < 0) {
		*error_r = t_strdup_printf(
			"Can't set minimum protocol to '%s' "
			"(ssl_min_protocol setting): Unknown value",
			ssl_set->ssl_min_protocol);
		return -1;
	}
	if (ldap_set_opt(ld, LDAP_OPT_X_TLS_PROTOCOL_MIN, &opt,
			 "ssl_min_protocol", ssl_set->ssl_min_protocol,
			 error_r) < 0)
		return -1;

	opt = 0;
	ldap_set_option(ld, LDAP_OPT_X_TLS_NEWCTX, &opt);

	return 0;
}
#endif

static int ldap_set_tls_validate_file(const char *file, const char *name,
				      const char **error_r)
{
	if (*file != '\0' && !settings_file_has_path(file)) {
		*error_r = t_strdup_printf("LDAP doesn't support inline content for %s", name);
		return -1;
	}
	return 0;
}

int ldap_set_tls_validate(const struct ssl_settings *set, const char **error_r)
{
	return ldap_set_tls_validate_file(set->ssl_client_ca_file,
					  "ssl_client_ca_file", error_r) < 0 ||
	       ldap_set_tls_validate_file(set->ssl_client_cert_file,
					  "ssl_client_cert_file", error_r) < 0 ||
	       ldap_set_tls_validate_file(set->ssl_client_key_file,
					  "ssl_client_key_file", error_r) < 0 ?
		-1 : 0;
}

void ldap_init_defaults(void)
{
	static bool ldap_global_initialized = FALSE;
	if (!ldap_global_initialized) {
		/* Enforce reading the global ldap.conf file. It is
		   done only when ld parameter is NULL. We'll override the
		   global version for connections. */
		int version = LDAP_VERSION3;
		(void)ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &version);
		ldap_global_initialized = TRUE;
	}
}
