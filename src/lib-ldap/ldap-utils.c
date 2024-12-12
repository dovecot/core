/* Copyright (c) 2024 Dovecot authors */

#include "lib.h"
#include "ldap-utils.h"
#include "ssl-settings.h"
#include "settings-parser.h"

void ldap_set_opt(const char *prefix, LDAP *ld, int opt, const void *value,
		  const char *optname, const char *value_str)
{
	int ret;

	ret = ldap_set_option(ld, opt, value);
	if (ret != LDAP_SUCCESS) {
		i_fatal("%sCan't set option %s to %s: %s",
			prefix, optname, value_str, ldap_err2string(ret));
	}
}

void ldap_set_opt_str(const char *prefix, LDAP *ld, int opt, const char *value,
		      const char *optname)
{
	if (*value != '\0')
		ldap_set_opt(prefix, ld, opt, value, optname, value);
}

#ifndef LDAP_OPT_X_TLS
void ldap_set_tls_options(const char *prefix ATTR_UNUSED, LDAP *ld ATTR_UNUSED,
			  bool starttls ATTR_UNUSED, const char *uris ATTR_UNUSED,
			  const struct ssl_settings *ssl_set ATTR_UNUSED) { }
#else

void ldap_set_tls_options(const char *prefix, LDAP *ld, bool starttls,
			  const char *uris, const struct ssl_settings *ssl_set)
{
	if (!starttls && strstr(uris, "ldaps:") == NULL)
		return;

	struct settings_file key_file, cert_file, ca_file;
	settings_file_get(ssl_set->ssl_client_key_file,
			  unsafe_data_stack_pool, &key_file);
	settings_file_get(ssl_set->ssl_client_cert_file,
			  unsafe_data_stack_pool, &cert_file);
	settings_file_get(ssl_set->ssl_client_ca_file,
			  unsafe_data_stack_pool, &ca_file);

	ldap_set_opt_str(prefix, ld, LDAP_OPT_X_TLS_CACERTFILE,
			 ca_file.path, "ssl_client_ca_file");
	ldap_set_opt_str(prefix, ld, LDAP_OPT_X_TLS_CACERTDIR,
			 ssl_set->ssl_client_ca_dir, "ssl_client_ca_dir");
	ldap_set_opt_str(prefix, ld, LDAP_OPT_X_TLS_CERTFILE,
			 cert_file.path, "ssl_client_cert_file");
	ldap_set_opt_str(prefix, ld, LDAP_OPT_X_TLS_KEYFILE,
			 key_file.path, "ssl_client_key_file");
	ldap_set_opt_str(prefix, ld, LDAP_OPT_X_TLS_CIPHER_SUITE,
			 ssl_set->ssl_cipher_list, "ssl_cipher_list");
	ldap_set_opt_str(prefix, ld, LDAP_OPT_X_TLS_PROTOCOL_MIN,
			 ssl_set->ssl_min_protocol, "ssl_min_protocol");
	ldap_set_opt_str(prefix, ld, LDAP_OPT_X_TLS_ECNAME,
			 ssl_set->ssl_curve_list, "ssl_curve_list");

	bool requires = ssl_set->ssl_client_require_valid_cert;
	int opt = requires ? LDAP_OPT_X_TLS_HARD : LDAP_OPT_X_TLS_ALLOW;

	/* required for Bookworm */
	ldap_set_opt(prefix, NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &opt,
		     "ssl_client_require_valid_cert", requires ? "yes" : "no" );

	/* required for RHEL9 */
	ldap_set_opt(prefix, ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &opt,
		     "ssl_client_require_valid_cert", requires ? "yes" : "no");
}

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

#endif
