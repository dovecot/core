/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "iostream-ssl.h"

int io_stream_create_ssl(struct ssl_iostream_context *ctx ATTR_UNUSED,
			 const char *source ATTR_UNUSED,
			 const struct ssl_iostream_settings *set ATTR_UNUSED,
			 struct istream **input ATTR_UNUSED,
			 struct ostream **output ATTR_UNUSED,
			 struct ssl_iostream **iostream_r)
{
	*iostream_r = NULL;
	return -1;
}

void ssl_iostream_unref(struct ssl_iostream **ssl_io ATTR_UNUSED)
{
}

int ssl_iostream_handshake(struct ssl_iostream *ssl_io ATTR_UNUSED)
{
	return -1;
}
void ssl_iostream_set_handshake_callback(struct ssl_iostream *ssl_io ATTR_UNUSED,
					 int (*callback)(void *context) ATTR_UNUSED,
					 void *context ATTR_UNUSED) {}

bool ssl_iostream_is_handshaked(const struct ssl_iostream *ssl_io ATTR_UNUSED) { return FALSE; }
bool ssl_iostream_has_valid_client_cert(const struct ssl_iostream *ssl_io ATTR_UNUSED) { return FALSE; }
bool ssl_iostream_has_broken_client_cert(struct ssl_iostream *ssl_io ATTR_UNUSED) { return TRUE; }
int ssl_iostream_cert_match_name(struct ssl_iostream *ssl_io ATTR_UNUSED, const char *name ATTR_UNUSED) { return -1; }
const char *ssl_iostream_get_peer_name(struct ssl_iostream *ssl_io ATTR_UNUSED) { return NULL; }
const char *ssl_iostream_get_security_string(struct ssl_iostream *ssl_io ATTR_UNUSED) { return NULL; }
const char *ssl_iostream_get_last_error(struct ssl_iostream *ssl_io ATTR_UNUSED) { return NULL; }

int ssl_iostream_generate_params(buffer_t *output ATTR_UNUSED)
{
	return -1;
}
int ssl_iostream_context_import_params(struct ssl_iostream_context *ctx ATTR_UNUSED,
				       const buffer_t *input ATTR_UNUSED)
{
	return -1;
}

int ssl_iostream_context_init_client(const char *source ATTR_UNUSED,
				     const struct ssl_iostream_settings *set ATTR_UNUSED,
				     struct ssl_iostream_context **ctx_r ATTR_UNUSED)
{
	return -1;
}

int ssl_iostream_context_init_server(const char *source ATTR_UNUSED,
				     const struct ssl_iostream_settings *set ATTR_UNUSED,
				     struct ssl_iostream_context **ctx_r)
{
	*ctx_r = NULL;
	return -1;
}

void ssl_iostream_context_deinit(struct ssl_iostream_context **ctx ATTR_UNUSED)
{
}
