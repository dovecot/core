#ifndef IOSTREAM_SSL_PRIVATE_H
#define IOSTREAM_SSL_PRIVATE_H

#include "iostream-ssl.h"

struct iostream_ssl_vfuncs {
	int (*context_init_client)(const struct ssl_iostream_settings *set,
				   struct ssl_iostream_context **ctx_r,
				   const char **error_r);
	int (*context_init_server)(const struct ssl_iostream_settings *set,
				   struct ssl_iostream_context **ctx_r,
				   const char **error_r);
	void (*context_deinit)(struct ssl_iostream_context *ctx);

	int (*generate_params)(buffer_t *output, const char **error_r);
	int (*context_import_params)(struct ssl_iostream_context *ctx,
				     const buffer_t *input);

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

	void (*set_log_prefix)(struct ssl_iostream *ssl_io, const char *prefix);
	bool (*is_handshaked)(const struct ssl_iostream *ssl_io);
	bool (*has_handshake_failed)(const struct ssl_iostream *ssl_io);
	bool (*has_valid_client_cert)(const struct ssl_iostream *ssl_io);
	bool (*has_broken_client_cert)(struct ssl_iostream *ssl_io);
	int (*cert_match_name)(struct ssl_iostream *ssl_io, const char *name);
	const char *(*get_peer_name)(struct ssl_iostream *ssl_io);
	const char *(*get_server_name)(struct ssl_iostream *ssl_io);
	const char *(*get_security_string)(struct ssl_iostream *ssl_io);
	const char *(*get_last_error)(struct ssl_iostream *ssl_io);
};

#endif
