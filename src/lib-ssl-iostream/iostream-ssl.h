#ifndef IOSTREAM_SSL_H
#define IOSTREAM_SSL_H

struct ssl_iostream;
struct ssl_iostream_context;

struct ssl_iostream_settings {
	const char *cipher_list;
	const char *ca, *ca_dir;
	const char *cert;
	const char *key;
	const char *key_password;
	const char *cert_username_field;
	const char *crypto_device;

	bool verbose, verbose_invalid_cert;
	bool verify_remote_cert;
	bool require_valid_cert;
};

int io_stream_create_ssl(struct ssl_iostream_context *ctx, const char *source,
			 const struct ssl_iostream_settings *set,
			 struct istream **input, struct ostream **output,
			 struct ssl_iostream **iostream_r);
/* returned input and output streams must also be unreferenced */
void ssl_iostream_unref(struct ssl_iostream **ssl_io);
/* shutdown SSL connection and unreference ssl iostream */
void ssl_iostream_destroy(struct ssl_iostream **ssl_io);

int ssl_iostream_handshake(struct ssl_iostream *ssl_io);
void ssl_iostream_set_handshake_callback(struct ssl_iostream *ssl_io,
					 int (*callback)(void *context),
					 void *context);

bool ssl_iostream_is_handshaked(const struct ssl_iostream *ssl_io);
bool ssl_iostream_has_valid_client_cert(const struct ssl_iostream *ssl_io);
bool ssl_iostream_has_broken_client_cert(struct ssl_iostream *ssl_io);
int ssl_iostream_cert_match_name(struct ssl_iostream *ssl_io, const char *name);
const char *ssl_iostream_get_peer_name(struct ssl_iostream *ssl_io);
const char *ssl_iostream_get_security_string(struct ssl_iostream *ssl_io);
const char *ssl_iostream_get_last_error(struct ssl_iostream *ssl_io);

int ssl_iostream_generate_params(buffer_t *output);
int ssl_iostream_context_import_params(struct ssl_iostream_context *ctx,
				       const buffer_t *input);

int ssl_iostream_context_init_client(const char *source,
				     const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r);
int ssl_iostream_context_init_server(const char *source,
				     const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r);
void ssl_iostream_context_deinit(struct ssl_iostream_context **ctx);

#endif
