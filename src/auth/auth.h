#ifndef __AUTH_H
#define __AUTH_H

#include "auth-interface.h"

typedef void (*AuthCallback) (AuthReplyData *reply, const unsigned char *data,
			      void *context);

typedef struct {
	AuthMethod method;

	void (*init)(unsigned int login_pid,
		     AuthInitRequestData *request,
		     AuthCallback callback, void *context);
} AuthModule;

extern AuthMethod auth_methods;
extern const char *const *auth_realms;

void auth_register_module(AuthModule *module);
void auth_unregister_module(AuthModule *module);

void auth_init_request(unsigned int login_pid,
		       AuthInitRequestData *request,
		       AuthCallback callback, void *context);
void auth_continue_request(unsigned int login_pid,
			   AuthContinuedRequestData *request,
			   const unsigned char *data,
			   AuthCallback callback, void *context);

void auth_init(void);
void auth_deinit(void);

#endif
