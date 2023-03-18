#ifndef AUTH_SASL_H
#define AUTH_SASL_H

struct mech_module {
	const char *mech_name;
};

/*
 * Mechanisms
 */

void mech_register_module(const struct mech_module *module);
void mech_unregister_module(const struct mech_module *module);
const struct mech_module *mech_module_find(const char *name);

#endif
