#ifndef __USERDB_H
#define __USERDB_H

struct auth_request;

typedef void userdb_callback_t(const char *result,
			       struct auth_request *request);

struct userdb_module {
	const char *name;

	/* If blocking is set to TRUE, use child processes to access
	   this passdb. */
	int blocking;

	void (*preinit)(const char *args);
	void (*init)(const char *args);
	void (*deinit)(void);

	void (*lookup)(struct auth_request *auth_request,
		       userdb_callback_t *callback);
};

uid_t userdb_parse_uid(struct auth_request *request, const char *str);
gid_t userdb_parse_gid(struct auth_request *request, const char *str);

void userdb_preinit(struct auth *auth, const char *data);
void userdb_init(struct auth *auth);
void userdb_deinit(struct auth *auth);

#include "auth-request.h"

#endif
