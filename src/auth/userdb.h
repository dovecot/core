#ifndef __USERDB_H
#define __USERDB_H

#include "auth-request.h"

struct user_data {
	const char *virtual_user;
	const char *home;
	const char *mail;

	const char *system_user;
	uid_t uid;
	gid_t gid;
};

typedef void userdb_callback_t(const struct user_data *user, void *context);

struct userdb_module {
	const char *name;

	void (*preinit)(const char *args);
	void (*init)(const char *args);
	void (*deinit)(void);

	void (*lookup)(struct auth_request *auth_request,
		       userdb_callback_t *callback, void *context);
};

uid_t userdb_parse_uid(struct auth_request *request, const char *str);
gid_t userdb_parse_gid(struct auth_request *request, const char *str);

void userdb_preinit(struct auth *auth, const char *data);
void userdb_init(struct auth *auth);
void userdb_deinit(struct auth *auth);

#endif
