#ifndef __USERDB_H
#define __USERDB_H

#include "auth-stream.h"

struct auth_request;

typedef void userdb_callback_t(struct auth_stream_reply *reply,
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

void userdb_preinit(struct auth *auth, const char *driver, const char *args);
void userdb_init(struct auth_userdb *passdb);
void userdb_deinit(struct auth_userdb *passdb);

#include "auth-request.h"

#endif
