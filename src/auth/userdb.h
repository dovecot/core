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

extern struct userdb_module *userdb;

extern struct userdb_module userdb_passdb;
extern struct userdb_module userdb_static;
extern struct userdb_module userdb_passwd;
extern struct userdb_module userdb_passwd_file;
extern struct userdb_module userdb_vpopmail;
extern struct userdb_module userdb_ldap;
extern struct userdb_module userdb_sql;

uid_t userdb_parse_uid(struct auth_request *request, const char *str);
gid_t userdb_parse_gid(struct auth_request *request, const char *str);

void userdb_preinit(void);
void userdb_init(void);
void userdb_deinit(void);

#endif
