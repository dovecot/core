#ifndef AUTH_SASL_H
#define AUTH_SASL_H

struct mech_module {
	const char *mech_name;

	enum mech_security_flags flags;
	enum mech_passdb_need passdb_need;

	struct auth_request *(*auth_new)(void);
	void (*auth_initial)(struct auth_request *request,
			     const unsigned char *data, size_t data_size);
	void (*auth_continue)(struct auth_request *request,
			      const unsigned char *data, size_t data_size);
	void (*auth_free)(struct auth_request *request);
};

/*
 * Mechanisms
 */

void mech_register_module(const struct mech_module *module);
void mech_unregister_module(const struct mech_module *module);
const struct mech_module *mech_module_find(const char *name);

#endif
