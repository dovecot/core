#ifndef __PASSDB_H
#define __PASSDB_H

#include "mech.h"

#define IS_VALID_PASSWD(pass) \
	((pass)[0] != '\0' && (pass)[0] != '*' && (pass)[0] != '!')

enum passdb_credentials {
	_PASSDB_CREDENTIALS_INTERNAL = -1,

	PASSDB_CREDENTIALS_PLAINTEXT,
	PASSDB_CREDENTIALS_CRYPT,
	PASSDB_CREDENTIALS_DIGEST_MD5
};

enum passdb_result {
	PASSDB_RESULT_USER_UNKNOWN = -1,
	PASSDB_RESULT_USER_DISABLED = -2,
	PASSDB_RESULT_INTERNAL_FAILURE = -3,

	PASSDB_RESULT_PASSWORD_MISMATCH = 0,
	PASSDB_RESULT_OK = 1,
};

typedef void verify_plain_callback_t(enum passdb_result result,
				     struct auth_request *request);
typedef void lookup_credentials_callback_t(const char *result,
					   struct auth_request *request);

struct passdb_module {
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

void passdb_handle_credentials(enum passdb_credentials credentials,
			       const char *user, const char *password,
			       const char *scheme,
			       lookup_credentials_callback_t *callback,
                               struct auth_request *auth_request);

extern struct passdb_module *passdb;

extern struct passdb_module passdb_passwd;
extern struct passdb_module passdb_shadow;
extern struct passdb_module passdb_passwd_file;
extern struct passdb_module passdb_pam;
extern struct passdb_module passdb_vpopmail;
extern struct passdb_module passdb_ldap;

void passdb_init(void);
void passdb_deinit(void);

#endif
