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
	   ssl_iostream_settings_string_offsets[] */
	const char *protocols; /* both */
	const char *cipher_list; /* both */
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
/* returned input and output streams must also be unreferenced */
void ssl_iostream_unref(struct ssl_iostream **ssl_io);
/* shutdown SSL connection and unreference ssl iostream */
void ssl_iostream_destroy(struct ssl_iostream **ssl_io);

/* If verbose logging is enabled, use the specified log prefix */
void ssl_iostream_set_log_prefix(struct ssl_iostream *ssl_io,
				 const char *prefix);

int ssl_iostream_handshake(struct ssl_iostream *ssl_io);
/* Call the given callback when SSL handshake finishes. The callback must
   verify whether the certificate and its hostname is valid. If there is no
   callback, the default is to use ssl_iostream_check_cert_validity() with the
   same host as given to io_stream_create_ssl_client() */
void ssl_iostream_set_handshake_callback(struct ssl_iostream *ssl_io,
					 ssl_iostream_handshake_callback_t *callback,
					 void *context);

bool ssl_iostream_is_handshaked(const struct ssl_iostream *ssl_io);
/* Returns TRUE if the remote cert is invalid, or handshake callback returned
   failure. */
bool ssl_iostream_has_handshake_failed(const struct ssl_iostream *ssl_io);
bool ssl_iostream_has_valid_client_cert(const struct ssl_iostream *ssl_io);
bool ssl_iostream_has_broken_client_cert(struct ssl_iostream *ssl_io);
int ssl_iostream_check_cert_validity(struct ssl_iostream *ssl_io,
				     const char *host, const char **error_r);
int ssl_iostream_cert_match_name(struct ssl_iostream *ssl_io, const char *name);
const char *ssl_iostream_get_peer_name(struct ssl_iostream *ssl_io);
const char *ssl_iostream_get_compression(struct ssl_iostream *ssl_io);
const char *ssl_iostream_get_server_name(struct ssl_iostream *ssl_io);
const char *ssl_iostream_get_security_string(struct ssl_iostream *ssl_io);
const char *ssl_iostream_get_last_error(struct ssl_iostream *ssl_io);

int ssl_iostream_context_init_client(const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r,
				     const char **error_r);
int ssl_iostream_context_init_server(const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r,
				     const char **error_r);
void ssl_iostream_context_deinit(struct ssl_iostream_context **ctx);

struct ssl_iostream_settings *ssl_iostream_settings_dup(pool_t pool,
			const struct ssl_iostream_settings *old_set);
void ssl_iostream_settings_init_from(pool_t pool,
				     struct ssl_iostream_settings *dest,
				     const struct ssl_iostream_settings *src);

#endif
