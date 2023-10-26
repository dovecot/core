#ifndef SASL_SERVER_GSSAPI_H
#define SASL_SERVER_GSSAPI_H

void sasl_server_mech_register_gssapi(struct sasl_server_instance *sinst);
void sasl_server_mech_unregister_gssapi(struct sasl_server_instance *sinst);

void sasl_server_mech_register_gss_spnego(struct sasl_server_instance *sinst);
void sasl_server_mech_unregister_gss_spnego(struct sasl_server_instance *sinst);

#endif
