#ifndef IOSTREAM_OPENSSL_H
#define IOSTREAM_OPENSSL_H

#include "iostream-ssl-private.h"

#include <openssl/ssl.h>

struct ssl_iostream_context {
	SSL_CTX *ssl_ctx;

	pool_t pool;
	const struct ssl_iostream_settings *set;

	DH *dh_512, *dh_1024;
	int username_nid;

	unsigned int client_ctx:1;
};

struct ssl_iostream {
	int refcount;
	struct ssl_iostream_context *ctx;

	SSL *ssl;
	BIO *bio_ext;

	struct istream *plain_input;
	struct ostream *plain_output;
	struct ostream *ssl_output;

	char *host;
	char *last_error;
	char *log_prefix;
	int plain_stream_errno;

	/* copied settings */
	bool verbose, verbose_invalid_cert, require_valid_cert;
	int username_nid;

	ssl_iostream_handshake_callback_t *handshake_callback;
	void *handshake_context;

	unsigned int handshaked:1;
	unsigned int handshake_failed:1;
	unsigned int cert_received:1;
	unsigned int cert_broken:1;
	unsigned int want_read:1;
	unsigned int input_handler:1;
	unsigned int ostream_flush_waiting_input:1;
	unsigned int closed:1;
};

extern int dovecot_ssl_extdata_index;

struct istream *openssl_i_stream_create_ssl(struct ssl_iostream *ssl_io);
struct ostream *openssl_o_stream_create_ssl(struct ssl_iostream *ssl_io);

int openssl_iostream_context_init_client(const struct ssl_iostream_settings *set,
					 struct ssl_iostream_context **ctx_r,
					 const char **error_r);
int openssl_iostream_context_init_server(const struct ssl_iostream_settings *set,
					 struct ssl_iostream_context **ctx_r,
					 const char **error_r);
void openssl_iostream_context_deinit(struct ssl_iostream_context *ctx);

int openssl_iostream_load_key(const struct ssl_iostream_settings *set,
			      EVP_PKEY **pkey_r, const char **error_r);
const char *ssl_iostream_get_use_certificate_error(const char *cert);
int openssl_cert_match_name(SSL *ssl, const char *verify_name);
int openssl_get_protocol_options(const char *protocols);
#define OPENSSL_ALL_PROTOCOL_OPTIONS \
	(SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1)

/* Sync plain_input/plain_output streams with BIOs. Returns TRUE if at least
   one byte was read/written. */
bool openssl_iostream_bio_sync(struct ssl_iostream *ssl_io);
/* Call when there's more data available in plain_input/plain_output.
   Returns 1 if it's ok to continue with SSL_read/SSL_write, 0 if not
   (still handshaking), -1 if error occurred. */
int openssl_iostream_more(struct ssl_iostream *ssl_io);

/* Returns 1 if the operation should be retried (we read/wrote more data),
   0 if the operation should retried later once more data has been
   read/written, -1 if a fatal error occurred (errno is set). */
int openssl_iostream_handle_error(struct ssl_iostream *ssl_io, int ret,
				  const char *func_name);
int openssl_iostream_handle_write_error(struct ssl_iostream *ssl_io, int ret,
					const char *func_name);

const char *openssl_iostream_error(void);
const char *openssl_iostream_key_load_error(void);

int openssl_iostream_generate_params(buffer_t *output, const char **error_r);
int openssl_iostream_context_import_params(struct ssl_iostream_context *ctx,
					   const buffer_t *input);
void openssl_iostream_context_free_params(struct ssl_iostream_context *ctx);

#endif
