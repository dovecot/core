#ifndef IOSTREAM_OPENSSL_H
#define IOSTREAM_OPENSSL_H

#include "iostream-ssl-private.h"

#include <openssl/ssl.h>

#ifndef HAVE_ASN1_STRING_GET0_DATA
#  define ASN1_STRING_get0_data(str) ASN1_STRING_data(str)
#endif
enum openssl_iostream_sync_type {
	OPENSSL_IOSTREAM_SYNC_TYPE_FIRST_READ,
	OPENSSL_IOSTREAM_SYNC_TYPE_CONTINUE_READ,
	OPENSSL_IOSTREAM_SYNC_TYPE_WRITE,
	OPENSSL_IOSTREAM_SYNC_TYPE_HANDSHAKE
};

struct ssl_iostream_context {
	int refcount;
	SSL_CTX *ssl_ctx;

	pool_t pool;
	struct ssl_iostream_settings set;

	int username_nid;

	bool client_ctx:1;
};

struct ssl_iostream {
	int refcount;
	struct ssl_iostream_context *ctx;

	SSL *ssl;
	BIO *bio_ext;

	struct istream *plain_input;
	struct ostream *plain_output;
	struct istream *ssl_input;
	struct ostream *ssl_output;

	/* SSL clients: host where we connected to */
	char *connected_host;
	/* SSL servers: host requested by the client via SNI */
	char *sni_host;
	char *last_error;
	char *log_prefix;
	char *plain_stream_errstr;
	int plain_stream_errno;

	/* copied settings */
	bool verbose, verbose_invalid_cert, allow_invalid_cert;
	int username_nid;

	ssl_iostream_handshake_callback_t *handshake_callback;
	void *handshake_context;

	ssl_iostream_sni_callback_t *sni_callback;
	void *sni_context;

	bool handshaked:1;
	bool handshake_failed:1;
	bool cert_received:1;
	bool cert_broken:1;
	bool want_read:1;
	bool ostream_flush_waiting_input:1;
	bool closed:1;
	bool destroyed:1;
};

extern int dovecot_ssl_extdata_index;

struct istream *openssl_i_stream_create_ssl(struct ssl_iostream *ssl_io);
struct ostream *openssl_o_stream_create_ssl(struct ssl_iostream *ssl_io);

int openssl_iostream_global_init(const struct ssl_iostream_settings *set,
				 const char **error_r);

int openssl_iostream_context_init_client(const struct ssl_iostream_settings *set,
					 struct ssl_iostream_context **ctx_r,
					 const char **error_r);
int openssl_iostream_context_init_server(const struct ssl_iostream_settings *set,
					 struct ssl_iostream_context **ctx_r,
					 const char **error_r);
void openssl_iostream_context_ref(struct ssl_iostream_context *ctx);
void openssl_iostream_context_unref(struct ssl_iostream_context *ctx);
void openssl_iostream_global_deinit(void);

int openssl_iostream_load_key(const struct ssl_iostream_cert *set,
			      EVP_PKEY **pkey_r, const char **error_r);
bool openssl_cert_match_name(SSL *ssl, const char *verify_name,
			     const char **reason_r);
#define OPENSSL_ALL_PROTOCOL_OPTIONS \
	(SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1)
/* opt_r is used with SSL_set_options() and version_r is used with
   SSL_set_min_proto_version(). Using either method should enable the same SSL
   protocol versions. */
int openssl_min_protocol_to_options(const char *min_protocol, long *opt_r,
				    int *version_r) ATTR_NULL(2,3);

/* Sync plain_input/plain_output streams with BIOs. Returns TRUE if at least
   one byte was read/written. */
bool openssl_iostream_bio_sync(struct ssl_iostream *ssl_io,
			       enum openssl_iostream_sync_type type);
/* Call when there's more data available in plain_input/plain_output.
   Returns 1 if it's ok to continue with SSL_read/SSL_write, 0 if not
   (still handshaking), -1 if error occurred. */
int openssl_iostream_more(struct ssl_iostream *ssl_io,
			  enum openssl_iostream_sync_type type);

/* Returns 1 if the operation should be retried (we read/wrote more data),
   0 if the operation should retried later once more data has been
   read/written, -1 if a fatal error occurred (errno is set). */
int openssl_iostream_handle_error(struct ssl_iostream *ssl_io, int ret,
				  enum openssl_iostream_sync_type type,
				  const char *func_name);

/* Perform clean shutdown for the connection. */
void openssl_iostream_shutdown(struct ssl_iostream *ssl_io);

void openssl_iostream_set_error(struct ssl_iostream *ssl_io, const char *str);
const char *openssl_iostream_error(void);
const char *openssl_iostream_key_load_error(void);
const char *
openssl_iostream_use_certificate_error(const char *cert, const char *set_name);
void openssl_iostream_clear_errors(void);

void ssl_iostream_openssl_init(void);
void ssl_iostream_openssl_deinit(void);

#endif
