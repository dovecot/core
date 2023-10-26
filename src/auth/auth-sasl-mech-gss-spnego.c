/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "sasl-server.h"
#include "sasl-server-gssapi.h"
#include "auth-sasl.h"
#include "auth-sasl-gssapi.h"

#ifdef HAVE_GSSAPI_SPNEGO

static struct auth_sasl_mech_module mech_gss_spnego;

static bool
mech_gss_spnego_register(struct sasl_server_instance *sasl_inst,
			 const struct auth_settings *set ATTR_UNUSED)
{
	sasl_server_mech_register_gss_spnego(sasl_inst);
	return TRUE;
}

static void
mech_gss_spnego_unregister(struct sasl_server_instance *sasl_inst)
{
	sasl_server_mech_unregister_gss_spnego(sasl_inst);
}

static struct auth_sasl_mech_module mech_gss_spnego = {
	.mech_name = SASL_MECH_NAME_GSS_SPNEGO,

	.mech_register = mech_gss_spnego_register,
	.mech_unregister = mech_gss_spnego_unregister,
};

#ifdef BUILTIN_GSSAPI
void auth_sasl_mech_gss_spnego_register(void)
{
	auth_sasl_mech_register_module(&mech_gss_spnego);
}
#else
void mech_gss_spnego_init(void);
void mech_gss_spnego_deinit(void);

void mech_gss_spnego_init(void)
{
	auth_sasl_mech_register_module(&mech_gss_spnego);
}

void mech_gss_spnego_deinit(void)
{
	auth_sasl_mech_unregister_module(&mech_gss_spnego);
}
#endif

#endif
