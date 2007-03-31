#ifndef __PASSDB_H
#define __PASSDB_H

#define IS_VALID_PASSWD(pass) \
	((pass)[0] != '\0' && (pass)[0] != '*' && (pass)[0] != '!')

struct auth_request;

enum passdb_credentials {
	_PASSDB_CREDENTIALS_INTERNAL = -1,

	PASSDB_CREDENTIALS_PLAINTEXT,
	PASSDB_CREDENTIALS_CRYPT,
	PASSDB_CREDENTIALS_CRAM_MD5,
	PASSDB_CREDENTIALS_DIGEST_MD5,
	PASSDB_CREDENTIALS_LANMAN,
	PASSDB_CREDENTIALS_NTLM,
	PASSDB_CREDENTIALS_OTP,
	PASSDB_CREDENTIALS_SKEY,
	PASSDB_CREDENTIALS_RPA
};

enum passdb_result {
	PASSDB_RESULT_INTERNAL_FAILURE = -1,
	PASSDB_RESULT_SCHEME_NOT_AVAILABLE = -2,

	PASSDB_RESULT_USER_UNKNOWN = -3,
	PASSDB_RESULT_USER_DISABLED = -4,
	PASSDB_RESULT_PASS_EXPIRED = -5,

	PASSDB_RESULT_PASSWORD_MISMATCH = 0,
	PASSDB_RESULT_OK = 1
};

typedef void verify_plain_callback_t(enum passdb_result result,
				     struct auth_request *request);
typedef void lookup_credentials_callback_t(enum passdb_result result,
					   const char *password,
					   struct auth_request *request);
typedef void set_credentials_callback_t(enum passdb_result result,
					struct auth_request *request);

struct passdb_module_interface {
	const char *name;

	struct passdb_module *
		(*preinit)(struct auth_passdb *auth_passdb, const char *args);
	void (*init)(struct passdb_module *module, const char *args);
	void (*deinit)(struct passdb_module *module);

	/* Check if plaintext password matches */
	void (*verify_plain)(struct auth_request *request, const char *password,
			     verify_plain_callback_t *callback);

	/* Return authentication credentials, set in
	   auth_request->credentials. */
	void (*lookup_credentials)(struct auth_request *request, 
				   lookup_credentials_callback_t *callback);

	/* Update credentials */
	int (*set_credentials)(struct auth_request *request,
			       const char *new_credentials,
			       set_credentials_callback_t *callback);
};

struct passdb_module {
	/* The caching key for this module, or NULL if caching isn't wanted. */
	const char *cache_key;
	/* Default password scheme for this module.
	   If cache_key is set, must not be NULL. */
	const char *default_pass_scheme;
	/* If blocking is set to TRUE, use child processes to access
	   this passdb. */
	bool blocking;

	struct passdb_module_interface iface;
};

const char *
passdb_get_credentials(struct auth_request *auth_request,
		       const char *password, const char *scheme);

void passdb_handle_credentials(enum passdb_result result,
			       const char *password, const char *scheme,
			       lookup_credentials_callback_t *callback,
                               struct auth_request *auth_request);

const char *passdb_credentials_to_str(enum passdb_credentials credentials,
				      const char *wanted_scheme);

struct auth_passdb *passdb_preinit(struct auth *auth, const char *driver,
				   const char *args, unsigned int id);
void passdb_init(struct auth_passdb *passdb);
void passdb_deinit(struct auth_passdb *passdb);

#include "auth-request.h"

#endif
