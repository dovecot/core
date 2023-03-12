/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ldap-sasl.h"
#include "db-ldap.h"
#include "db-ldap-sasl.h"

#if defined(BUILTIN_LDAP) || defined(PLUGIN_BUILD)

#include <stddef.h>
#include <unistd.h>

#ifndef LDAP_SASL_QUIET
#  define LDAP_SASL_QUIET 0 /* Doesn't exist in Solaris LDAP */
#endif

struct db_ldap_sasl_bind_context {
	const char *authcid;
	const char *passwd;
	const char *realm;
	const char *authzid;
};

#ifdef HAVE_LDAP_SASL
static int
sasl_interact(LDAP *ld ATTR_UNUSED, unsigned int flags ATTR_UNUSED,
	      void *defaults, void *interact)
{
	struct db_ldap_sasl_bind_context *context = defaults;
	sasl_interact_t *in;
	const char *str;

	for (in = interact; in->id != SASL_CB_LIST_END; in++) {
		switch (in->id) {
		case SASL_CB_GETREALM:
			str = context->realm;
			break;
		case SASL_CB_AUTHNAME:
			str = context->authcid;
			break;
		case SASL_CB_USER:
			str = context->authzid;
			break;
		case SASL_CB_PASS:
			str = context->passwd;
			break;
		default:
			str = NULL;
			break;
		}
		if (str != NULL) {
			in->len = strlen(str);
			in->result = str;
		}
	}
	return LDAP_SUCCESS;
}

int db_ldap_bind_sasl_interactive(struct ldap_connection *conn)
{
	struct db_ldap_sasl_bind_context context;

	i_zero(&context);
	context.authcid = conn->set->auth_dn;
	context.passwd = conn->set->auth_dn_password;
	context.realm = conn->set->auth_sasl_realm;
	context.authzid = conn->set->auth_sasl_authz_id;

	const char *mechs = t_array_const_string_join(
		&conn->set->auth_sasl_mechanisms, " ");

	/* There doesn't seem to be a way to do SASL binding
	   asynchronously.. */
	return ldap_sasl_interactive_bind_s(conn->ld, NULL, mechs,
					    NULL, NULL, LDAP_SASL_QUIET,
					    sasl_interact, &context);
}
#else
int db_ldap_bind_sasl_interactive(struct ldap_connection *conn ATTR_UNUSED)
{
	i_unreached(); /* already checked at init */
}
#endif

#endif
