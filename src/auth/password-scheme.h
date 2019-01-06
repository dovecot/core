#ifndef PASSWORD_SCHEME_H
#define PASSWORD_SCHEME_H

#define AUTH_LOG_MSG_PASSWORD_MISMATCH "Password mismatch"

struct hash_method;

enum password_encoding {
	PW_ENCODING_NONE,
	PW_ENCODING_BASE64,
	PW_ENCODING_HEX
};

struct password_generate_params {
	const char *user;
	unsigned int rounds;
};

struct password_scheme {
	const char *name;
	enum password_encoding default_encoding;
	/* If non-zero, this is the expected raw password length.
	   It can be used to automatically detect encoding between
	   hex and base64 encoded passwords. */
	unsigned int raw_password_len;

	int (*password_verify)(const char *plaintext,
			       const struct password_generate_params *params,
			       const unsigned char *raw_password, size_t size,
			       const char **error_r);
	void (*password_generate)(const char *plaintext,
				  const struct password_generate_params *params,
				  const unsigned char **raw_password_r,
				  size_t *size_r);
};
ARRAY_DEFINE_TYPE(password_scheme_p, const struct password_scheme *);
void password_schemes_get(ARRAY_TYPE(password_scheme_p) *schemes_r);

extern unsigned int password_scheme_encryption_rounds;

/* Returns 1 = matched, 0 = didn't match, -1 = unknown scheme or invalid
   raw_password */
int password_verify(const char *plaintext,
		    const struct password_generate_params *params,
		    const char *scheme,
		    const unsigned char *raw_password, size_t size,
		    const char **error_r);

/* Extracts scheme from password, or returns NULL if it isn't found.
   If auth_request is given, it's used for debug logging. */
const char *password_get_scheme(const char **password);

/* Decode encoded (base64/hex) password to raw form. Returns 1 if ok,
   0 if scheme is unknown, -1 if password is invalid. */
int password_decode(const char *password, const char *scheme,
		    const unsigned char **raw_password_r, size_t *size_r,
		    const char **error_r);

/* Create password with wanted scheme out of plaintext password and username.
   Potential base64/hex directives are ignored in scheme. Returns FALSE if
   the scheme is unknown. */
bool password_generate(const char *plaintext,
		       const struct password_generate_params *params,
		       const char *scheme,
		       const unsigned char **raw_password_r, size_t *size_r);
/* Like above, but generate encoded passwords. If hex/base64 directive isn't
   specified in the scheme, the default encoding for the scheme is used.
   Returns FALSE if the scheme is unknown. */
bool password_generate_encoded(const char *plaintext,
			       const struct password_generate_params *params,
			       const char *scheme, const char **password_r);

/* Returns TRUE if schemes are equivalent. */
bool password_scheme_is_alias(const char *scheme1, const char *scheme2);

/* Try to detect in which scheme crypted password is. Returns the scheme name
   or NULL if nothing was found. */
const char *
password_scheme_detect(const char *plain_password, const char *crypted_password,
		       const struct password_generate_params *params);

void password_scheme_register(const struct password_scheme *scheme);
void password_scheme_unregister(const struct password_scheme *scheme);

void password_schemes_init(void);
void password_schemes_deinit(void);

/* some password schemes/algorithms supports a variable number of
   encryption rounds. */
void password_set_encryption_rounds(unsigned int rounds);

/* INTERNAL: */
const char *password_generate_salt(size_t len);
const char *password_generate_md5_crypt(const char *pw, const char *salt);
int password_generate_otp(const char *pw, const char *state_data,
			  unsigned int algo, const char **result_r)
	ATTR_NULL(2);
void password_generate_rpa(const char *pw, unsigned char result[]);

int crypt_verify(const char *plaintext,
		 const struct password_generate_params *params,
		 const unsigned char *raw_password, size_t size,
		 const char **error_r);

int scram_scheme_parse(const struct hash_method *hmethod, const char *name,
		       const unsigned char *credentials, size_t size,
		       unsigned int *iter_count_r, const char **salt_r,
		       unsigned char stored_key_r[],
		       unsigned char server_key_r[], const char **error_r);
int scram_verify(const struct hash_method *hmethod, const char *scheme_name,
		 const char *plaintext, const unsigned char *raw_password,
		 size_t size, const char **error_r);
void scram_generate(const struct hash_method *hmethod, const char *plaintext,
		    const unsigned char **raw_password_r, size_t *size_r);

int scram_sha1_verify(const char *plaintext,
		      const struct password_generate_params *params ATTR_UNUSED,
		      const unsigned char *raw_password, size_t size,
		      const char **error_r ATTR_UNUSED);
void scram_sha1_generate(const char *plaintext,
			 const struct password_generate_params *params ATTR_UNUSED,
			 const unsigned char **raw_password_r, size_t *size_r);

void pbkdf2_generate(const char *plaintext,
		     const struct password_generate_params *params ATTR_UNUSED,
		     const unsigned char **raw_password_r, size_t *size_r);
int pbkdf2_verify(const char *plaintext,
		  const struct password_generate_params *params ATTR_UNUSED,
		  const unsigned char *raw_password, size_t size,
		  const char **error_r);

/* check which of the algorithms Blowfish, SHA-256 and SHA-512 are
   supported by the used libc's/glibc's crypt() */
void password_scheme_register_crypt(void);

#ifdef HAVE_LIBSODIUM
void password_scheme_register_sodium(void);
#endif

#endif
