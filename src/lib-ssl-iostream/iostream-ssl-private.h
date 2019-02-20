#ifndef IOSTREAM_SSL_PRIVATE_H
#define IOSTREAM_SSL_PRIVATE_H

#include "iostream-ssl.h"

struct iostream_ssl_vfuncs {
	int (*global_init)(const struct ssl_iostream_settings *set,
			   const char **error_r);
	int (*context_init_client)(const struct ssl_iostream_settings *set,
				   struct ssl_iostream_context **ctx_r,
				   const char **error_r);
	int (*context_init_server)(const struct ssl_iostream_settings *set,
				   struct ssl_iostream_context **ctx_r,
				   const char **error_r);
	void (*context_ref)(struct ssl_iostream_context *ctx);
	void (*context_unref)(struct ssl_iostream_context *ctx);

	int (*create)(struct ssl_iostream_context *ctx, const char *host,
		      const struct ssl_iostream_settings *set,
		      struct istream **input, struct ostream **output,
		      struct ssl_iostream **iostream_r, const char **error_r);
	void (*unref)(struct ssl_iostream *ssl_io);
	void (*destroy)(struct ssl_iostream *ssl_io);

	int (*handshake)(struct ssl_iostream *ssl_io);
	void (*set_handshake_callback)(struct ssl_iostream *ssl_io,
				       ssl_iostream_handshake_callback_t *callback,
				       void *context);
	void (*set_sni_callback)(struct ssl_iostream *ssl_io,
				 ssl_iostream_sni_callback_t *callback,
				 void *context);
	void (*change_context)(struct ssl_iostream *ssl_io,
			       struct ssl_iostream_context *ctx);

	void (*set_log_prefix)(struct ssl_iostream *ssl_io, const char *prefix);
	bool (*is_handshaked)(const struct ssl_iostream *ssl_io);
	bool (*has_handshake_failed)(const struct ssl_iostream *ssl_io);
	bool (*has_valid_client_cert)(const struct ssl_iostream *ssl_io);
	bool (*has_broken_client_cert)(struct ssl_iostream *ssl_io);
	bool (*cert_match_name)(struct ssl_iostream *ssl_io, const char *name,
				const char **reason_r);
	const char *(*get_peer_name)(struct ssl_iostream *ssl_io);
	const char *(*get_server_name)(struct ssl_iostream *ssl_io);
	const char *(*get_compression)(struct ssl_iostream *ssl_io);
	const char *(*get_security_string)(struct ssl_iostream *ssl_io);
	const char *(*get_last_error)(struct ssl_iostream *ssl_io);
	const char *(*get_cipher)(struct ssl_iostream *ssl_io, unsigned int *bits_r);
	const char *(*get_pfs)(struct ssl_iostream *ssl_io);
	const char *(*get_protocol_name)(struct ssl_iostream *ssl_io);
};

void iostream_ssl_module_init(const struct iostream_ssl_vfuncs *vfuncs);

/* Returns TRUE if both settings are equal. Note that NULL and "" aren't
   treated equal. */
bool ssl_iostream_settings_equals(const struct ssl_iostream_settings *set1,
				  const struct ssl_iostream_settings *set2);
/* Clear out all stream-only settings, so only settings useful for a context
   are left. */
void ssl_iostream_settings_drop_stream_only(struct ssl_iostream_settings *set);

void ssl_iostream_unref(struct ssl_iostream **ssl_io);

#endif
