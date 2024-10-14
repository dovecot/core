/* Copyright (c) 2024 Dovecot authors */

#include "lib.h"
#include "ldap-utils.h"
#include "ssl-settings.h"

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
void ldap_set_tls_options(const char *prefix ATTR_UNUSED,
			  bool starttls ATTR_UNUSED, const char *uris ATTR_UNUSED,
			  const struct ssl_settings *ssl_set ATTR_UNUSED) { }
#else

void ldap_set_tls_options(const char *prefix, bool starttls, const char *uris,
			  const struct ssl_settings *ssl_set)
{
	if (!starttls && strstr(uris, "ldaps:") == NULL)
		return;

	const char *ssl_client_ca_file = t_strcut(ssl_set->ssl_client_ca_file, '\n');
	ldap_set_opt_str(prefix, NULL, LDAP_OPT_X_TLS_CACERTFILE,
			 ssl_client_ca_file, "ssl_client_ca_file");

	ldap_set_opt_str(prefix, NULL, LDAP_OPT_X_TLS_CACERTDIR,
			 ssl_set->ssl_client_ca_dir, "ssl_client_ca_dir");

	const char *ssl_client_cert_file = t_strcut(ssl_set->ssl_client_cert_file, '\n');
	ldap_set_opt_str(prefix, NULL, LDAP_OPT_X_TLS_CERTFILE,
			 ssl_client_cert_file, "ssl_client_cert_file");

	const char *ssl_client_key_file = t_strcut(ssl_set->ssl_client_key_file, '\n');
	ldap_set_opt_str(prefix, NULL, LDAP_OPT_X_TLS_KEYFILE,
			 ssl_client_key_file, "ssl_client_key_file");

	ldap_set_opt_str(prefix, NULL, LDAP_OPT_X_TLS_CIPHER_SUITE,
			 ssl_set->ssl_cipher_list, "ssl_cipher_list");
	ldap_set_opt_str(prefix, NULL, LDAP_OPT_X_TLS_PROTOCOL_MIN,
			 ssl_set->ssl_min_protocol, "ssl_min_protocol");
	ldap_set_opt_str(prefix, NULL, LDAP_OPT_X_TLS_ECNAME,
			 ssl_set->ssl_curve_list, "ssl_curve_list");

	bool requires = ssl_set->ssl_client_require_valid_cert;
	int opt = requires ? LDAP_OPT_X_TLS_HARD : LDAP_OPT_X_TLS_NEVER;
	ldap_set_opt(prefix, NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &opt,
		     "ssl_client_require_valid_cert", requires ? "yes" : "no" );
}

#endif
