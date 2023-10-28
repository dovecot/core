#ifndef AUTH_SASL_MECH_GSSAPI_H
#define AUTH_SASL_MECH_GSSAPI_H

#include "sasl-server-gssapi.h"

void auth_sasl_mech_gssapi_settings_init(
	const struct auth_settings *set,
	struct sasl_server_gssapi_settings *gss_set_r);

#ifdef BUILTIN_GSSAPI
void auth_sasl_mech_gssapi_register(void);
void auth_sasl_mech_gss_spnego_register(void);
#endif

#endif
