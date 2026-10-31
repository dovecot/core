/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dsasl-client-private.h"
#include "dsasl-client-gssapi-settings.h"

#ifdef HAVE_GSSAPI
/* The module is src/lib-dovecot-gssapi/libdovecot-gssapi. It has no init
   function: the symbol that registers the mechanisms is looked up instead. */
static const char *const gssapi_mech_names[] = {
	SASL_MECH_NAME_GSSAPI, SASL_MECH_NAME_GSS_SPNEGO, NULL
};
#endif

static const struct dsasl_client_module dsasl_client_modules[] = {
#ifdef HAVE_GSSAPI
	{
		.name = "dovecot-gssapi",
		.init_symbol = "dsasl_client_init_gssapi",
		.mech_names = gssapi_mech_names,
		.settings_equal = dsasl_client_gssapi_settings_equal,
	},
#endif
	{ .name = NULL }
};

static const struct dsasl_client_module *
dsasl_client_module_find(const char *mech_name)
{
	const struct dsasl_client_module *module;
	const char *const *names;

	for (module = dsasl_client_modules; module->name != NULL; module++) {
		for (names = module->mech_names; *names != NULL; names++) {
			if (strcasecmp(*names, mech_name) == 0)
				return module;
		}
	}
	return NULL;
}

int dsasl_client_module_load_mech(struct dsasl_client *client,
				  const char *mech_name, const char **error_r)
{
	const struct dsasl_client_module *module =
		dsasl_client_module_find(mech_name);

	if (module == NULL)
		return 0;
	if (dsasl_client_module_load(client, module, error_r) < 0)
		return -1;
	return 1;
}

int dsasl_client_module_settings_equal(struct event *event1,
				       struct event *event2,
				       const char **error_r)
{
	const struct dsasl_client_module *module;
	const char *const *names;
	int ret;

	for (module = dsasl_client_modules; module->name != NULL; module++) {
		if (module->settings_equal == NULL)
			continue;
		for (names = module->mech_names; *names != NULL; names++) {
			ret = dsasl_client_mech_name_settings_equal(
				*names, module->settings_equal,
				event1, event2, error_r);
			if (ret <= 0)
				return ret;
		}
	}
	return 1;
}
