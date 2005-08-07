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
	PASSDB_CREDENTIALS_RPA
};

enum passdb_result {
	PASSDB_RESULT_USER_UNKNOWN = -1,
	PASSDB_RESULT_USER_DISABLED = -2,
	PASSDB_RESULT_INTERNAL_FAILURE = -3,
	PASSDB_RESULT_SCHEME_NOT_AVAILABLE = -4,

	PASSDB_RESULT_PASSWORD_MISMATCH = 0,
	PASSDB_RESULT_OK = 1,
};

typedef void verify_plain_callback_t(enum passdb_result result,
				     struct auth_request *request);
typedef void lookup_credentials_callback_t(enum passdb_result result,
					   const char *credentials,
					   struct auth_request *request);

struct passdb_module {
	const char *name;

	/* The caching key for this module, or NULL if caching isn't wanted. */
	const char *cache_key;
	/* Default password scheme for this module.
	   If cache_key is set, must not be NULL. */
	const char *default_pass_scheme;
	/* If blocking is set to TRUE, use child processes to access
	   this passdb. */
	int blocking;

	void (*preinit)(const char *args);
	void (*init)(const char *args);
	void (*deinit)(void);

	/* Check if plaintext password matches */
	void (*verify_plain)(struct auth_request *request, const char *password,
			     verify_plain_callback_t *callback);

	/* Return authentication credentials. Type is authentication mechanism
	   specific value that is requested. */
	void (*lookup_credentials)(struct auth_request *request, 
				   enum passdb_credentials credentials,
				   lookup_credentials_callback_t *callback);
};

void passdb_handle_credentials(enum passdb_result result,
			       enum passdb_credentials credentials,
			       const char *password, const char *scheme,
			       lookup_credentials_callback_t *callback,
                               struct auth_request *auth_request);

const char *passdb_credentials_to_str(enum passdb_credentials credentials);

void passdb_preinit(struct auth *auth, const char *driver, const char *args);
void passdb_init(struct auth_passdb *passdb);
void passdb_deinit(struct auth_passdb *passdb);

#include "auth-request.h"

#endif
