#ifndef IOSTREAM_SSL_PRIVATE_H
#define IOSTREAM_SSL_PRIVATE_H

#include "iostream-ssl.h"

struct iostream_ssl_vfuncs {
	int (*context_init_client)(const char *source,
				   const struct ssl_iostream_settings *set,
				   struct ssl_iostream_context **ctx_r);
	int (*context_init_server)(const char *source,
				   const struct ssl_iostream_settings *set,
				   struct ssl_iostream_context **ctx_r);
	void (*context_deinit)(struct ssl_iostream_context *ctx);

	int (*generate_params)(buffer_t *output);
	int (*context_import_params)(struct ssl_iostream_context *ctx,
				     const buffer_t *input);

	int (*create)(struct ssl_iostream_context *ctx, const char *source,
		      const struct ssl_iostream_settings *set,
		      struct istream **input, struct ostream **output,
		      struct ssl_iostream **iostream_r);
	void (*unref)(struct ssl_iostream *ssl_io);
	void (*destroy)(struct ssl_iostream *ssl_io);

	int (*handshake)(struct ssl_iostream *ssl_io);
	void (*set_handshake_callback)(struct ssl_iostream *ssl_io,
				       int (*callback)(void *context),
				       void *context);

	bool (*is_handshaked)(const struct ssl_iostream *ssl_io);
	bool (*has_valid_client_cert)(const struct ssl_iostream *ssl_io);
	bool (*has_broken_client_cert)(struct ssl_iostream *ssl_io);
	int (*cert_match_name)(struct ssl_iostream *ssl_io, const char *name);
	const char *(*get_peer_name)(struct ssl_iostream *ssl_io);
	const char *(*get_security_string)(struct ssl_iostream *ssl_io);
	const char *(*get_last_error)(struct ssl_iostream *ssl_io);
};

#endif
