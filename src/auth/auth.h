#ifndef __AUTH_H
#define __AUTH_H

#include "auth-interface.h"

typedef void (*AuthCallback)(struct auth_reply_data *reply,
			     const unsigned char *data, void *context);

struct auth_module {
	enum auth_method method;

	void (*init)(unsigned int login_pid,
		     struct auth_init_request_data *request,
		     AuthCallback callback, void *context);
};

extern enum auth_method auth_methods;
extern const char *const *auth_realms;

void auth_register_module(struct auth_module *module);
void auth_unregister_module(struct auth_module *module);

void auth_init_request(unsigned int login_pid,
		       struct auth_init_request_data *request,
		       AuthCallback callback, void *context);
void auth_continue_request(unsigned int login_pid,
			   struct auth_continued_request_data *request,
			   const unsigned char *data,
			   AuthCallback callback, void *context);

void auth_init(void);
void auth_deinit(void);

#endif
