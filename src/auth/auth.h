#ifndef __AUTH_H
#define __AUTH_H

#include "auth-interface.h"

typedef void (*auth_callback_t)(struct auth_reply_data *reply,
				const void *data, void *context);

struct auth_module {
	enum auth_mech mech;

	void (*init)(unsigned int login_pid,
		     struct auth_init_request_data *request,
		     auth_callback_t callback, void *context);
};

extern enum auth_mech auth_mechanisms;
extern const char *const *auth_realms;

void auth_register_module(struct auth_module *module);
void auth_unregister_module(struct auth_module *module);

void auth_init_request(unsigned int login_pid,
		       struct auth_init_request_data *request,
		       auth_callback_t callback, void *context);
void auth_continue_request(unsigned int login_pid,
			   struct auth_continued_request_data *request,
			   const unsigned char *data,
			   auth_callback_t callback, void *context);

void auth_cyrus_sasl_init_lib(void);
void auth_cyrus_sasl_init(unsigned int login_pid,
			  struct auth_init_request_data *request,
			  auth_callback_t callback, void *context);

void auth_init(void);
void auth_deinit(void);

#endif
