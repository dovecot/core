/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "sasl-server.h"
#include "auth-sasl.h"
#include "auth-sasl-gssapi.h"

void auth_sasl_mech_gssapi_settings_init(
	const struct auth_settings *set,
	struct sasl_server_gssapi_settings *gss_set_r)
{
	i_zero(gss_set_r);
	gss_set_r->hostname = set->gssapi_hostname;
	gss_set_r->krb5_keytab = set->krb5_keytab;
}
