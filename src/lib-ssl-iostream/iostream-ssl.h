#ifndef IOSTREAM_SSL_H
#define IOSTREAM_SSL_H

struct ssl_iostream;
struct ssl_iostream_context;

struct ssl_iostream_settings {
	const char *protocols;
	const char *cipher_list;
	const char *ca, *ca_file, *ca_dir; /* context-only */
	const char *cert;
	const char *key;
	const char *key_password;
	const char *cert_username_field;
	const char *crypto_device; /* context-only */

	bool verbose, verbose_invalid_cert; /* stream-only */
	bool verify_remote_cert; /* neither/both */
	bool require_valid_cert; /* stream-only */
};

/* Returns 0 if ok, -1 and sets error_r if failed. The returned error string
   becomes available via ssl_iostream_get_last_error() */
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
const char *ssl_iostream_get_server_name(struct ssl_iostream *ssl_io);
const char *ssl_iostream_get_security_string(struct ssl_iostream *ssl_io);
const char *ssl_iostream_get_last_error(struct ssl_iostream *ssl_io);

int ssl_iostream_generate_params(buffer_t *output, const char **error_r);
int ssl_iostream_context_import_params(struct ssl_iostream_context *ctx,
				       const buffer_t *input);

int ssl_iostream_context_init_client(const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r,
				     const char **error_r);
int ssl_iostream_context_init_server(const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r,
				     const char **error_r);
void ssl_iostream_context_deinit(struct ssl_iostream_context **ctx);

#endif
