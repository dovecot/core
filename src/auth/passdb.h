#ifndef __PASSDB_H
#define __PASSDB_H

#define IS_VALID_PASSWD(pass) \
	((pass)[0] != '\0' && (pass)[0] != '*' && (pass)[0] != '!')

enum passdb_credentials {
	PASSDB_CREDENTIALS_PLAINTEXT,
	PASSDB_CREDENTIALS_DIGEST_MD5
};

enum passdb_result {
	PASSDB_RESULT_USER_UNKNOWN = -1,
	PASSDB_RESULT_USER_DISABLED = -2,
	PASSDB_RESULT_INTERNAL_FAILURE = -3,

	PASSDB_RESULT_PASSWORD_MISMATCH = 0,
	PASSDB_RESULT_OK = 1,
};

struct passdb_module {
	void (*init)(const char *args);
	void (*deinit)(void);

	/* Check if plaintext password matches */
	enum passdb_result (*verify_plain)(const char *user, const char *realm,
					   const char *password);

	/* Return authentication credentials. Type is authentication mechanism
	   specific value that is requested. */
	const char *(*lookup_credentials)(const char *user, const char *realm,
					  enum passdb_credentials credentials);
};

const char *passdb_credentials_to_str(enum passdb_credentials credentials);

extern struct passdb_module *passdb;

extern struct passdb_module passdb_passwd;
extern struct passdb_module passdb_shadow;
extern struct passdb_module passdb_passwd_file;
extern struct passdb_module passdb_pam;
extern struct passdb_module passdb_vpopmail;

void passdb_init(void);
void passdb_deinit(void);

#endif
