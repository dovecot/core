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

	int (*create)(struct ssl_iostream_context *ctx,
		      struct event *event_parent,
		      const char *host,
		      bool client,
		      enum ssl_iostream_flags flags,
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
	bool (*get_allow_invalid_cert)(struct ssl_iostream *ssl_io);
	const char *(*get_peer_username)(struct ssl_iostream *ssl_io);
	const char *(*get_server_name)(struct ssl_iostream *ssl_io);
	const char *(*get_compression)(struct ssl_iostream *ssl_io);
	const char *(*get_security_string)(struct ssl_iostream *ssl_io);
	const char *(*get_last_error)(struct ssl_iostream *ssl_io);
	const char *(*get_cipher)(struct ssl_iostream *ssl_io, unsigned int *bits_r);
	const char *(*get_pfs)(struct ssl_iostream *ssl_io);
	const char *(*get_protocol_name)(struct ssl_iostream *ssl_io);
	enum ssl_iostream_protocol_version
	(*get_protocol_version)(struct ssl_iostream *ssl_io);
	const char *(*get_ja3)(struct ssl_iostream *ssl_io);

	const char *(*get_application_protocol)(struct ssl_iostream *ssl_io);
	void (*set_application_protocols)(struct ssl_iostream_context *ctx,
					  const char *const *names);

	int (*get_channel_binding)(struct ssl_iostream *ssl_io,
				   const char *type, const buffer_t **data_r,
				   const char **error_r);
};

void iostream_ssl_module_init(const struct iostream_ssl_vfuncs *vfuncs);

/* Returns TRUE if both settings are equal. Note that NULL and "" aren't
   treated equal. */
bool ssl_iostream_settings_equals(const struct ssl_iostream_settings *set1,
				  const struct ssl_iostream_settings *set2);

void ssl_iostream_unref(struct ssl_iostream **ssl_io);

#endif
