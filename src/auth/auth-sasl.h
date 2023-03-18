#ifndef AUTH_SASL_H
#define AUTH_SASL_H

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
