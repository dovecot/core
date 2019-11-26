#ifndef IOSTREAM_SSL_H
#define IOSTREAM_SSL_H

struct ssl_iostream;
struct ssl_iostream_context;

struct ssl_iostream_cert {
	const char *cert;
	const char *key;
	const char *key_password;
};

struct ssl_iostream_settings {
	/* NOTE: when updating, remember to update:
	   ssl_iostream_settings_string_offsets[],
	   ssl_iostream_settings_drop_stream_only() */
	const char *min_protocol; /* both */
	const char *cipher_list; /* both */
	const char *ciphersuites; /* both, TLSv1.3 only */
	const char *curve_list; /* both */
	const char *ca, *ca_file, *ca_dir; /* context-only */
	/* alternative cert is for providing certificate using
	   different key algorithm */
	struct ssl_iostream_cert cert; /* both */
	struct ssl_iostream_cert alt_cert; /* both */
	const char *dh; /* context-only */
	const char *cert_username_field; /* both */
	const char *crypto_device; /* context-only */

	bool verbose, verbose_invalid_cert; /* stream-only */
	bool skip_crl_check; /* context-only */
	bool verify_remote_cert; /* neither/both */
	bool allow_invalid_cert; /* stream-only */
	bool prefer_server_ciphers; /* both */
	bool compression; /* context-only */
	bool tickets; /* context-only */
};

/* Load SSL module */
int ssl_module_load(const char **error_r);

/* Returns 0 if ok, -1 and sets error_r if failed. The returned error string
   becomes available via ssl_iostream_get_last_error(). The callback most
   likely should be calling ssl_iostream_check_cert_validity(). */
typedef int
ssl_iostream_handshake_callback_t(const char **error_r, void *context);
/* Called when TLS SNI becomes available. */
typedef int ssl_iostream_sni_callback_t(const char *name, const char **error_r,
					void *context);

/* Explicitly initialize SSL library globally. This is also done automatically
   when the first SSL connection is created, but it may be useful to call it
   earlier in case of chrooting. After the initialization is successful, any
   further calls will just be ignored. Returns 0 on success, -1 on error. */
int io_stream_ssl_global_init(const struct ssl_iostream_settings *set,
			      const char **error_r);

int io_stream_create_ssl_client(struct ssl_iostream_context *ctx, const char *host,
				const struct ssl_iostream_settings *set,
				struct istream **input, struct ostream **output,
				struct ssl_iostream **iostream_r,
				const char **error_r);
int io_stream_create_ssl_server(struct ssl_iostream_context *ctx,
				const struct ssl_iostream_settings *set,
				struct istream **input, struct ostream **output,
				struct ssl_iostream **iostream_r,
				const char **error_r);
/* Shutdown SSL connection and unreference ssl iostream.
   The returned input and output streams must also be unreferenced. */
void ssl_iostream_destroy(struct ssl_iostream **ssl_io);

/* If verbose logging is enabled, use the specified log prefix */
void ssl_iostream_set_log_prefix(struct ssl_iostream *ssl_io,
				 const char *prefix);

int ssl_iostream_handshake(struct ssl_iostream *ssl_io);
/* Call the given callback when SSL handshake finishes. The callback must
   verify whether the certificate and its hostname is valid. If there is no
   callback, the default is to use ssl_iostream_check_cert_validity() with the
   same host as given to io_stream_create_ssl_client()

   Before the callback is called, certificate is only checked for issuer
   and validity period. You should call ssl_iostream_check_cert_validity()
   in your callback.
*/
void ssl_iostream_set_handshake_callback(struct ssl_iostream *ssl_io,
					 ssl_iostream_handshake_callback_t *callback,
					 void *context);
/* Call the given callback when client sends SNI. The callback can change the
   ssl_iostream's context (with different certificates) by using
   ssl_iostream_change_context(). */
void ssl_iostream_set_sni_callback(struct ssl_iostream *ssl_io,
				   ssl_iostream_sni_callback_t *callback,
				   void *context);
void ssl_iostream_change_context(struct ssl_iostream *ssl_io,
				 struct ssl_iostream_context *ctx);

bool ssl_iostream_is_handshaked(const struct ssl_iostream *ssl_io);
/* Returns TRUE if the remote cert is invalid, or handshake callback returned
   failure. */
bool ssl_iostream_has_handshake_failed(const struct ssl_iostream *ssl_io);
bool ssl_iostream_has_valid_client_cert(const struct ssl_iostream *ssl_io);
bool ssl_iostream_has_broken_client_cert(struct ssl_iostream *ssl_io);
/* Checks certificate validity based, also performs name checking. Called by
   default in handshake, unless handshake callback is set with
   ssl_iostream_check_cert_validity().

   Host should be set as the name you want to validate the certificate name(s)
   against. Usually this is the host name you connected to.

   This function is same as calling ssl_iostream_has_valid_client_cert()
   and ssl_iostream_cert_match_name().
 */
int ssl_iostream_check_cert_validity(struct ssl_iostream *ssl_io,
				     const char *host, const char **error_r);
/* Returns TRUE if the given name matches the SSL stream's certificate.
   The returned reason is a human-readable string explaining what exactly
   matched the name, or why nothing matched. Note that this function works
   only if the certificate was valid - using it when certificate is invalid
   will always return FALSE before even checking the hostname. */
bool ssl_iostream_cert_match_name(struct ssl_iostream *ssl_io, const char *name,
				  const char **reason_r);
const char *ssl_iostream_get_peer_name(struct ssl_iostream *ssl_io);
const char *ssl_iostream_get_compression(struct ssl_iostream *ssl_io);
const char *ssl_iostream_get_server_name(struct ssl_iostream *ssl_io);
const char *ssl_iostream_get_security_string(struct ssl_iostream *ssl_io);
/* Returns SSL context's current used cipher algorithm. Returns NULL
   if SSL handshake has not been performed.

   This returns values like 'AESGCM'
*/
const char *ssl_iostream_get_cipher(struct ssl_iostream *ssl_io,
				    unsigned int *bits_r);
/* Returns currently used forward secrecy algorithm, if available.
   Returns NULL if handshake not done yet, empty string if missing.

   This returns values like 'DH', 'ECDH' etc..
*/
const char *ssl_iostream_get_pfs(struct ssl_iostream *ssl_io);
/* Returns currently used SSL protocol name. Returns NULL if handshake
   has not yet been made.

   This returns values like SSLv3, TLSv1, TLSv1.1, TLSv1.2
*/
const char *ssl_iostream_get_protocol_name(struct ssl_iostream *ssl_io);

const char *ssl_iostream_get_last_error(struct ssl_iostream *ssl_io);

int ssl_iostream_context_init_client(const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r,
				     const char **error_r);
int ssl_iostream_context_init_server(const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r,
				     const char **error_r);
void ssl_iostream_context_ref(struct ssl_iostream_context *ctx);
void ssl_iostream_context_unref(struct ssl_iostream_context **ctx);

struct ssl_iostream_settings *ssl_iostream_settings_dup(pool_t pool,
			const struct ssl_iostream_settings *old_set);
void ssl_iostream_settings_init_from(pool_t pool,
				     struct ssl_iostream_settings *dest,
				     const struct ssl_iostream_settings *src);

/* Persistent cache of ssl_iostream_contexts. The context is permanently stored
   until ssl_iostream_context_cache_free() is called. The returned context
   must be unreferenced by the caller. */
int ssl_iostream_client_context_cache_get(const struct ssl_iostream_settings *set,
					  struct ssl_iostream_context **ctx_r,
					  const char **error_r);
int ssl_iostream_server_context_cache_get(const struct ssl_iostream_settings *set,
					  struct ssl_iostream_context **ctx_r,
					  const char **error_r);
void ssl_iostream_context_cache_free(void);

const char *ssl_iostream_get_fingerprint(struct ssl_iostream *ssl_io);
const char *ssl_iostream_get_fingerprint_base64(struct ssl_iostream *ssl_io);
const char *__ssl_iostream_get_fingerprint(struct ssl_iostream *ssl_io, bool base64mode);
char *__base64(const char *input, int length);

#endif
