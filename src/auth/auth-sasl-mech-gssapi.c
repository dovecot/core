/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "sasl-server.h"
#include "sasl-server-gssapi.h"
#include "auth-sasl.h"
#include "auth-sasl-gssapi.h"

static bool
mech_gssapi_register(struct sasl_server_instance *sasl_inst,
		     const struct auth_settings *set)
{
	struct sasl_server_gssapi_settings gss_set;

	auth_sasl_mech_gssapi_settings_init(set, &gss_set);
	sasl_server_mech_register_gssapi(sasl_inst, &gss_set);
	return TRUE;
}

static void
mech_gssapi_unregister(struct sasl_server_instance *sasl_inst)
{
	sasl_server_mech_unregister_gssapi(sasl_inst);
}

static struct auth_sasl_mech_module mech_gssapi = {
	.mech_name = SASL_MECH_NAME_GSSAPI,

	.mech_register = mech_gssapi_register,
	.mech_unregister = mech_gssapi_unregister,
};

#ifdef BUILTIN_GSSAPI
void auth_sasl_mech_gssapi_register(void)
{
	auth_sasl_mech_register_module(&mech_gssapi);
}
#else
void mech_gssapi_init(void);
void mech_gssapi_deinit(void);

void mech_gssapi_init(void)
{
	auth_sasl_mech_register_module(&mech_gssapi);
}

void mech_gssapi_deinit(void)
{
	auth_sasl_mech_unregister_module(&mech_gssapi);
}
#endif
