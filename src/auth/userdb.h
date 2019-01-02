#ifndef USERDB_H
#define USERDB_H

#include "md5.h"
#include "auth-fields.h"

struct auth;
struct auth_request;
struct auth_userdb_settings;

enum userdb_result {
	USERDB_RESULT_INTERNAL_FAILURE = -1,
	USERDB_RESULT_USER_UNKNOWN = -2,

	USERDB_RESULT_OK = 1
};

typedef void userdb_callback_t(enum userdb_result result,
			       struct auth_request *request);
/* user=NULL when there are no more users */
typedef void userdb_iter_callback_t(const char *user, void *context);

struct userdb_module {
	const char *args;
	/* The default caching key for this module, or NULL if caching isn't
	   wanted. This is updated by settings in auth_userdb. */
	const char *default_cache_key;

	/* If blocking is set to TRUE, use child processes to access
	   this userdb. */
	bool blocking;
        /* id is used by blocking userdb to identify the userdb */
	unsigned int id;

	/* number of time init() has been called */
	int init_refcount;

	/* WARNING: avoid adding anything here that isn't based on args.
	   if you do, you need to change userdb.c:userdb_find() also to avoid
	   accidentally merging wrong userdbs. */

	const struct userdb_module_interface *iface;
};

struct userdb_iterate_context {
	struct auth_request *auth_request;
	userdb_iter_callback_t *callback;
	void *context;
	bool failed;
};

struct userdb_module_interface {
	const char *name;

	struct userdb_module *(*preinit)(pool_t pool, const char *args);
	void (*init)(struct userdb_module *module);
	void (*deinit)(struct userdb_module *module);

	void (*lookup)(struct auth_request *auth_request,
		       userdb_callback_t *callback);

	struct userdb_iterate_context *
		(*iterate_init)(struct auth_request *auth_request,
				userdb_iter_callback_t *callback,
				void *context);
	void (*iterate_next)(struct userdb_iterate_context *ctx);
	int (*iterate_deinit)(struct userdb_iterate_context *ctx);
};

const char *userdb_result_to_string(enum userdb_result result);

uid_t userdb_parse_uid(struct auth_request *request, const char *str)
	ATTR_NULL(1);
gid_t userdb_parse_gid(struct auth_request *request, const char *str)
	ATTR_NULL(1);

struct userdb_module *
userdb_preinit(pool_t pool, const struct auth_userdb_settings *set);
void userdb_init(struct userdb_module *userdb);
void userdb_deinit(struct userdb_module *userdb);

void userdb_register_module(struct userdb_module_interface *iface);
void userdb_unregister_module(struct userdb_module_interface *iface);

void userdbs_generate_md5(unsigned char md5[STATIC_ARRAY MD5_RESULTLEN]);

void userdbs_init(void);
void userdbs_deinit(void);

#include "auth-request.h"

#endif
