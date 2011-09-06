#ifndef IOSTREAM_OPENSSL_H
#define IOSTREAM_OPENSSL_H

#include "iostream-ssl.h"

#include <openssl/ssl.h>

struct ssl_iostream_context {
	SSL_CTX *ssl_ctx;

	pool_t pool;
	const struct ssl_iostream_settings *set;
	/* Used as logging prefix, e.g. "client" or "server" */
	const char *source;

	DH *dh_512, *dh_1024;
	int username_nid;

	unsigned int client_ctx:1;
};

struct ssl_iostream {
	int refcount;
	struct ssl_iostream_context *ctx;

	const struct ssl_iostream_settings *set;

	SSL *ssl;
	BIO *bio_ext;

	struct istream *plain_input;
	struct ostream *plain_output;
	struct ostream *ssl_output;

	char *source;
	char *last_error;

	/* copied settings */
	bool verbose, verbose_invalid_cert, require_valid_cert;
	int username_nid;

	int (*handshake_callback)(void *context);
	void *handshake_context;

	unsigned int handshaked:1;
	unsigned int cert_received:1;
	unsigned int cert_broken:1;
	unsigned int want_read:1;
	unsigned int ostream_flush_waiting_input:1;
};

extern int dovecot_ssl_extdata_index;

struct istream *i_stream_create_ssl(struct ssl_iostream *ssl_io);
struct ostream *o_stream_create_ssl(struct ssl_iostream *ssl_io);
void ssl_iostream_unref(struct ssl_iostream **ssl_io);

int ssl_iostream_load_key(const struct ssl_iostream_settings *set,
			  const char *key_source, EVP_PKEY **pkey_r);
const char *ssl_iostream_get_use_certificate_error(const char *cert);

/* Sync plain_input/plain_output streams with BIOs. Returns TRUE if at least
   one byte was read/written. */
bool ssl_iostream_bio_sync(struct ssl_iostream *ssl_io);
/* Call when there's more data available in plain_input/plain_output.
   Returns 1 if it's ok to continue with SSL_read/SSL_write, 0 if not
   (still handshaking), -1 if error occurred. */
int ssl_iostream_more(struct ssl_iostream *ssl_io);

/* Returns 1 if the operation should be retried (we read/wrote more data),
   0 if the operation should retried later once more data has been
   read/written, -1 if a fatal error occurred (errno is set). */
int ssl_iostream_handle_error(struct ssl_iostream *ssl_io, int ret,
			      const char *func_name);

const char *ssl_iostream_error(void);
const char *ssl_iostream_key_load_error(void);

void ssl_iostream_context_free_params(struct ssl_iostream_context *ctx);

#endif
