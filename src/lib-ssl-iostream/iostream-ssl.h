#ifndef IOSTREAM_SSL_H
#define IOSTREAM_SSL_H

#include "settings-parser.h"
#include "ssl-settings.h"

struct ssl_iostream;
struct ssl_iostream_context;

#define SSL_CHANNEL_BIND_TYPE_TLS_UNIQUE "tls-unique"
#define SSL_CHANNEL_BIND_TYPE_TLS_EXPORTER "tls-exporter"

enum ssl_iostream_protocol_version {
	/* Version not yet known at this protocol stage */
	SSL_IOSTREAM_PROTOCOL_VERSION_UNKNOWN = 0,
	/* SSLv3 protocol */
	SSL_IOSTREAM_PROTOCOL_VERSION_SSL3,
	/* TLSv1.0 protocol */
	SSL_IOSTREAM_PROTOCOL_VERSION_TLS1,
	/* TLSv1.1 protocol */
	SSL_IOSTREAM_PROTOCOL_VERSION_TLS1_1,
	/* TLSv1.2 protocol */
	SSL_IOSTREAM_PROTOCOL_VERSION_TLS1_2,
	/* TLSv1.3 protocol */
	SSL_IOSTREAM_PROTOCOL_VERSION_TLS1_3,
	/* Protocol version newer than Dovecot recognizes. */
	SSL_IOSTREAM_PROTOCOL_VERSION_NEW,
};

enum ssl_iostream_flags {
	/* Enable ssl_iostream_settings.allow_invalid_cert after context is
	   already created. If the context already has
	   ssl_iostream_settings.allow_invalid_cert enabled, it can't
	   be anymore disabled. */
	SSL_IOSTREAM_FLAG_ALLOW_INVALID_CERT = BIT(0),
	/* Disable ssl_iostream_settings.ca_file and ca_dir settings in
	   io_stream_autocreate_ssl_client() when creating context. */
	SSL_IOSTREAM_FLAG_DISABLE_CA_FILES = BIT(1),
};

struct ssl_iostream_cert {
	struct settings_file cert;
	struct settings_file key;
	const char *key_password;
};

struct ssl_iostream_settings {
	/* NOTE: when adding fields, remember to update
	   ssl_iostream_settings_equals() */
	pool_t pool;

	const char *min_protocol;
	const char *cipher_list; /* TLSv1.2 and below only */
	const char *ciphersuites; /* TLSv1.3 only */
	const char *curve_list;
	struct settings_file ca;
	const char *ca_dir;
	struct ssl_iostream_cert cert;
	/* alternative cert is for providing certificate using
	   different key algorithm */
	struct ssl_iostream_cert alt_cert;
	struct settings_file dh;
	/* Field which contains the username returned by
	   ssl_iostream_get_peer_username() */
	const char *cert_username_field;
	const char *crypto_device;

	/* List of application protocol names */
	const char *const *application_protocols;

	/* If FALSE, check for CA CRLs. */
	bool skip_crl_check;
	/* server-only: Request client certificate. */
	bool verify_remote_cert;
	/* Don't fail the SSL handshake even if certificate isn't valid. */
	bool allow_invalid_cert;
	/* server-only: Use the server's configured cipher order rather than
	   the client's. */
	bool prefer_server_ciphers;
	/* Enable SSL compression (if the linked OpenSSL library is built
	   with support for it) */
	bool compression;
	/* If FALSE, set SSL_OP_NO_TICKET. See OpenSSL documentation. */
	bool tickets;
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
				struct event *event_parent,
				enum ssl_iostream_flags flags,
				struct istream **input, struct ostream **output,
				struct ssl_iostream **iostream_r,
				const char **error_r);
int io_stream_create_ssl_server(struct ssl_iostream_context *ctx,
				struct event *event_parent,
				struct istream **input, struct ostream **output,
				struct ssl_iostream **iostream_r,
				const char **error_r);

struct ssl_iostream_client_autocreate_parameters {
	struct event *event_parent;
	const char *host;
	enum ssl_iostream_flags flags;
	const char *const *application_protocols;
};

struct ssl_iostream_server_autocreate_parameters {
	struct event *event_parent;
	const char *const *application_protocols;
};

/* Lookup settings from event, use ssl_iostream_client_context_cache_get() to
   get the context and call io_stream_create_ssl_client(). */
int io_stream_autocreate_ssl_client(
	const struct ssl_iostream_client_autocreate_parameters *parameters,
	struct istream **input, struct ostream **output,
	struct ssl_iostream **iostream_r,
	const char **error_r);
/* Lookup settings from event, use ssl_iostream_server_context_cache_get() to
   get the context and call io_stream_create_ssl_server(). */
int io_stream_autocreate_ssl_server(
	const struct ssl_iostream_server_autocreate_parameters *parameters,
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
/* Returns if ssl_iostream_settings.allow_invalid_cert is set or
   SSL_IOSTREAM_FLAG_ALLOW_INVALID_CERT is used. */
bool ssl_iostream_get_allow_invalid_cert(struct ssl_iostream *ssl_io);
/* Returns username from the received certificate of the peer (client) if
   available, NULL if not. The username is based on cert_username_field
   setting. */
const char *ssl_iostream_get_peer_username(struct ssl_iostream *ssl_io);
/* Returns used compression, if any. Returns NULL if not available. */
const char *ssl_iostream_get_compression(struct ssl_iostream *ssl_io);
/* Returns TLS extension server_name(0) requested by client, or NULL if not
   provided.
 */
const char *ssl_iostream_get_server_name(struct ssl_iostream *ssl_io);
/* Returns textual representation of the security parameters for the connection,
   or NULL if handshake has not been done. */
const char *ssl_iostream_get_security_string(struct ssl_iostream *ssl_io);

/* Returns ClientHello based JA3 string. Will return NULL
   if it is not available due to no handshake performed, or
   OpenSSL version is earlier than 1.1. */
const char *ssl_iostream_get_ja3(struct ssl_iostream *ssl_io);

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
/* Returns currently used SSL protocol version. */
enum ssl_iostream_protocol_version
ssl_iostream_get_protocol_version(struct ssl_iostream *ssl_io);
/* Returns 0 if channel binding type is supported with channel binding data of
   requested type in data_r. Returns -1 if channel binding (of that type) is not
   supported and error message is returned in error_r. The ssl_io parameter
   may be NULL, in which case -1 is returned along with a generic error
   applicable to an insecure channel. */
int ssl_iostream_get_channel_binding(struct ssl_iostream *ssl_io,
				     const char *type, const buffer_t **data_r,
				     const char **error_r);

const char *ssl_iostream_get_last_error(struct ssl_iostream *ssl_io);

const char *ssl_iostream_get_application_protocol(struct ssl_iostream *ssl_io);

void ssl_iostream_context_set_application_protocols(struct ssl_iostream_context *ssl_ctx,
						    const char *const *names);

int ssl_iostream_context_init_client(const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r,
				     const char **error_r);
int ssl_iostream_context_init_server(const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r,
				     const char **error_r);
void ssl_iostream_context_ref(struct ssl_iostream_context *ctx);
void ssl_iostream_context_unref(struct ssl_iostream_context **ctx);

/* Persistent cache of ssl_iostream_contexts. The context is permanently stored
   until ssl_iostream_context_cache_free() is called. The returned context
   must be unreferenced by the caller.

   Returns 1 if new context was created, 0 if existing was re-used, and
   -1 on error.
*/
int ssl_iostream_client_context_cache_get(const struct ssl_iostream_settings *set,
					  struct ssl_iostream_context **ctx_r,
					  const char **error_r);
int ssl_iostream_server_context_cache_get(const struct ssl_iostream_settings *set,
					  struct ssl_iostream_context **ctx_r,
					  const char **error_r);
void ssl_iostream_context_cache_free(void);

#endif
