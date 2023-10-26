#ifndef AUTH_SASL_MECH_GSSAPI_H
#define AUTH_SASL_MECH_GSSAPI_H

#ifdef BUILTIN_GSSAPI
void auth_sasl_mech_gssapi_register(void);
void auth_sasl_mech_gss_spnego_register(void);
#endif

#endif
