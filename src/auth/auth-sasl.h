#ifndef AUTH_SASL_H
#define AUTH_SASL_H

/* Used only for string sanitization. */
#define AUTH_SASL_MAX_MECH_NAME_LEN 64

struct auth_sasl_mech_module {
	const char *mech_name;
};

/*
 * Mechanisms
 */

void auth_sasl_mech_register_module(
	const struct auth_sasl_mech_module *module);
void auth_sasl_mech_unregister_module(
	const struct auth_sasl_mech_module *module);
const struct auth_sasl_mech_module *
auth_sasl_mech_module_find(const char *name);

#endif
