#ifndef LDAP_UTILS_H
#define LDAP_UTILS_H

#include <ldap.h>

struct ssl_settings;

void ldap_set_opt(const char *prefix, LDAP *ld, int opt, const void *value,
		  const char *optname, const char *value_str);

void ldap_set_opt_str(const char *prefix, LDAP *ld, int opt, const char *value,
		      const char *optname);

void ldap_set_tls_options(const char *prefix, LDAP *ld, bool starttls,
			  const char *uris, const struct ssl_settings *ssl_set);
#endif
