#ifndef __USERDB_H
#define __USERDB_H

#include "auth-stream.h"

struct auth_request;

typedef void userdb_callback_t(struct auth_stream_reply *reply,
			       struct auth_request *request);

struct userdb_module {
	/* If blocking is set to TRUE, use child processes to access
	   this userdb. */
	int blocking;

	const struct userdb_module_interface *iface;
};

struct userdb_module_interface {
	const char *name;

	struct userdb_module *
		(*preinit)(struct auth_userdb *auth_userdb, const char *args);
	void (*init)(struct userdb_module *module, const char *args);
	void (*deinit)(struct userdb_module *module);

	void (*lookup)(struct auth_request *auth_request,
		       userdb_callback_t *callback);
};

uid_t userdb_parse_uid(struct auth_request *request, const char *str);
gid_t userdb_parse_gid(struct auth_request *request, const char *str);

void userdb_preinit(struct auth *auth, const char *driver, const char *args);
void userdb_init(struct auth_userdb *userdb);
void userdb_deinit(struct auth_userdb *userdb);

#include "auth-request.h"

#endif
