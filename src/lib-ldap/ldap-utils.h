#ifndef LDAP_UTILS_H
#define LDAP_UTILS_H

#include <ldap.h>

struct ssl_settings;

int ldap_set_opt(LDAP *ld, int opt, const void *value,
		 const char *optname, const char *value_str,
		 const char **error_r);

int ldap_set_opt_str(LDAP *ld, int opt, const char *value,
		     const char *optname, const char **error_r);

int ldap_set_tls_options(LDAP *ld, bool starttls, const char *uris,
			 const struct ssl_settings *ssl_set,
			 const char **error_r);

int ldap_set_tls_validate(const struct ssl_settings *set, const char **error_r);

#endif
