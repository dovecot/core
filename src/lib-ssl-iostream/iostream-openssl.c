/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"
#include "istream-private.h"
#include "ostream-private.h"
#include "iostream-openssl.h"

#include <openssl/rand.h>
#include <openssl/err.h>

static struct event_category event_category_ssl = {
	.name = "ssl",
};

static struct event_category event_category_ssl_client = {
	.parent = &event_category_ssl,
	.name = "ssl-client",
};

static struct event_category event_category_ssl_server = {
	.parent = &event_category_ssl,
	.name = "ssl-server",
};

static void openssl_iostream_free(struct ssl_iostream *ssl_io);

static void
openssl_iostream_set_error_full(struct ssl_iostream *ssl_io,
				const char *str, bool fallback_error)
{
	char *new_str;

	/* e_debug() may sometimes be overridden, making it write to this very
	   same SSL stream, in which case the provided str may be invalidated
	   before it is even used. Therefore, we duplicate it immediately. */
	new_str = i_strdup(str);

	/* This error should normally be logged by lib-ssl-iostream's caller.
	   But, log it here as well to make sure that the error is always logged.
	*/
	e_debug(ssl_io->event, "SSL error: %s", new_str);
	i_free(ssl_io->last_error);
	ssl_io->last_error = new_str;
	ssl_io->last_error_is_fallback = fallback_error;
}

void openssl_iostream_set_error(struct ssl_iostream *ssl_io, const char *str)
{
	openssl_iostream_set_error_full(ssl_io, str, FALSE);
}

static void openssl_info_callback(const SSL *ssl, int where, int ret)
{
	struct ssl_iostream *ssl_io;

	ssl_io = SSL_get_ex_data(ssl, dovecot_ssl_extdata_index);
	if ((where & SSL_CB_ALERT) != 0) {
		switch (ret & 0xff) {
		case SSL_AD_CLOSE_NOTIFY:
			e_debug(ssl_io->event, "SSL alert: %s",
				SSL_alert_desc_string_long(ret));
			break;
		default:
			e_debug(ssl_io->event, "SSL alert: where=0x%x, ret=%d: %s %s",
				where, ret,
				SSL_alert_type_string_long(ret),
				SSL_alert_desc_string_long(ret));
			break;
		}
	} else if (ret == 0) {
		e_debug(ssl_io->event, "SSL failed: where=0x%x: %s",
			where, SSL_state_string_long(ssl));
	} else {
		e_debug(ssl_io->event, "SSL: where=0x%x, ret=%d: %s",
			where, ret,
			SSL_state_string_long(ssl));
	}
}

static int
openssl_iostream_verify_client_cert(int preverify_ok, X509_STORE_CTX *ctx)
{
	int ssl_extidx = SSL_get_ex_data_X509_STORE_CTX_idx();
	SSL *ssl;
	struct ssl_iostream *ssl_io;
	char certname[1024];
	X509_NAME *subject;

	ssl = X509_STORE_CTX_get_ex_data(ctx, ssl_extidx);
	ssl_io = SSL_get_ex_data(ssl, dovecot_ssl_extdata_index);
	ssl_io->cert_received = TRUE;

	subject = X509_get_subject_name(X509_STORE_CTX_get_current_cert(ctx));
	if (subject == NULL ||
	    X509_NAME_oneline(subject, certname, sizeof(certname)) == NULL)
		certname[0] = '\0';
	else
		certname[sizeof(certname)-1] = '\0'; /* just in case.. */
	if (preverify_ok == 0) {
		openssl_iostream_set_error(ssl_io, t_strdup_printf(
			"Received invalid SSL certificate: %s: %s (check %s)",
			X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), certname,
			ssl_io->ctx->client_ctx ?
				"ssl_client_ca_* settings?" :
				"ssl_server_ca_file setting?"));
	} else {
		e_debug(ssl_io->event, "Received valid SSL certificate: %s", certname);
	}
	if (preverify_ok == 0) {
		ssl_io->cert_broken = TRUE;
		if (!ssl_io->allow_invalid_cert) {
			ssl_io->handshake_failed = TRUE;
			ssl_io->state = SSL_IOSTREAM_STATE_INVALID_CERT;
			return 0;
		}
	}
	return 1;
}

static void
openssl_iostream_set(struct ssl_iostream *ssl_io)
{
	int verify_flags;

	SSL_set_info_callback(ssl_io->ssl, openssl_info_callback);

	if (ssl_io->ctx->verify_remote_cert) {
		if (ssl_io->ctx->client_ctx)
			verify_flags = SSL_VERIFY_NONE;
		else
			verify_flags = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
		SSL_set_verify(ssl_io->ssl, verify_flags,
			       openssl_iostream_verify_client_cert);
	}
}

static int
openssl_iostream_create(struct ssl_iostream_context *ctx,
			struct event *event_parent, const char *host,
			bool client,
			enum ssl_iostream_flags flags,
			struct istream **input, struct ostream **output,
			struct ssl_iostream **iostream_r,
			const char **error_r)
{
	struct ssl_iostream *ssl_io;
	SSL *ssl;
	BIO *bio_int, *bio_ext;

	/* Don't allow an existing io_add_istream() to be use on the input.
	   It would seem to work, but it would also cause hangs. */
	i_assert(i_stream_get_root_io(*input)->real_stream->io == NULL);

	ssl = SSL_new(ctx->ssl_ctx);
	if (ssl == NULL) {
		*error_r = t_strdup_printf("SSL_new() failed: %s",
					   openssl_iostream_error());
		return -1;
	}

	/* BIO pairs use default buffer sizes (17 kB in OpenSSL 0.9.8e).
	   Each of the BIOs have one "write buffer". BIO_write() copies data
	   to them, while BIO_read() reads from the other BIO's write buffer
	   into the given buffer. The bio_int is used by OpenSSL and bio_ext
	   is used by this library. */
	if (BIO_new_bio_pair(&bio_int, 0, &bio_ext, 0) != 1) {
		*error_r = t_strdup_printf("BIO_new_bio_pair() failed: %s",
					   openssl_iostream_error());
		SSL_free(ssl);
		return -1;
	}

	ssl_io = i_new(struct ssl_iostream, 1);
	ssl_io->refcount = 1;
	ssl_io->ctx = ctx;
	ssl_iostream_context_ref(ssl_io->ctx);
	ssl_io->ssl = ssl;
	ssl_io->bio_ext = bio_ext;
	ssl_io->plain_input = *input;
	ssl_io->plain_output = *output;
	ssl_io->connected_host = i_strdup(host);
	ssl_io->event = event_create(event_parent);
	ssl_io->state = SSL_IOSTREAM_STATE_HANDSHAKING;
	ssl_io->allow_invalid_cert = ctx->allow_invalid_cert ||
		(flags & SSL_IOSTREAM_FLAG_ALLOW_INVALID_CERT) != 0;
	if (client)
		event_add_category(ssl_io->event, &event_category_ssl_client);
	else
		event_add_category(ssl_io->event, &event_category_ssl_server);
	if (host != NULL) {
		event_set_append_log_prefix(ssl_io->event,
					    t_strdup_printf("%s: ", host));
	}
	/* bio_int will be freed by SSL_free() */
	SSL_set_bio(ssl_io->ssl, bio_int, bio_int);
        SSL_set_ex_data(ssl_io->ssl, dovecot_ssl_extdata_index, ssl_io);
	SSL_set_tlsext_host_name(ssl_io->ssl, host);

	openssl_iostream_set(ssl_io);

	o_stream_uncork(ssl_io->plain_output);

	*input = openssl_i_stream_create_ssl(ssl_io);
	ssl_io->ssl_input = *input;

	*output = openssl_o_stream_create_ssl(ssl_io);
	i_stream_set_name(*input, t_strconcat("SSL ",
		i_stream_get_name(ssl_io->plain_input), NULL));
	o_stream_set_name(*output, t_strconcat("SSL ",
		o_stream_get_name(ssl_io->plain_output), NULL));

	if (ssl_io->plain_output->real_stream->error_handling_disabled)
		o_stream_set_no_error_handling(*output, TRUE);

	ssl_io->ssl_output = *output;
	*iostream_r = ssl_io;
	return 0;
}

static void openssl_iostream_free(struct ssl_iostream *ssl_io)
{
	ssl_iostream_context_unref(&ssl_io->ctx);
	o_stream_unref(&ssl_io->plain_output);
	i_stream_unref(&ssl_io->plain_input);
	BIO_free(ssl_io->bio_ext);
	SSL_free(ssl_io->ssl);
	i_free(ssl_io->cert_fp);
	i_free(ssl_io->pubkey_fp);
	i_free(ssl_io->ja3_str);
	i_free(ssl_io->plain_stream_errstr);
	i_free(ssl_io->last_error);
	i_free(ssl_io->connected_host);
	i_free(ssl_io->sni_host);
	event_unref(&ssl_io->event);
	i_free(ssl_io);
}

static void openssl_iostream_unref(struct ssl_iostream *ssl_io)
{
	i_assert(ssl_io->refcount > 0);
	if (--ssl_io->refcount > 0)
		return;

	i_assert(ssl_io->destroyed);
	openssl_iostream_free(ssl_io);
}

void openssl_iostream_shutdown(struct ssl_iostream *ssl_io)
{
	if (ssl_io->destroyed)
		return;

	i_assert(ssl_io->ssl_input != NULL);
	i_assert(ssl_io->ssl_output != NULL);

	ssl_io->destroyed = TRUE;
	(void)o_stream_flush(ssl_io->plain_output);

	if (!ssl_io->closed &&
	    (ssl_io->handshaked || ssl_io->handshake_failed || ssl_io->do_shutdown)) {
		/* Try shutting down connection. If it does not succeed at once,
		   try once more. */
		for (int i = 0; i < 2; i++) {
			openssl_iostream_clear_errors();
			int ret = SSL_shutdown(ssl_io->ssl);
			if (ret == 1)
				break;
			else if (ret == 0)
				openssl_iostream_bio_sync(ssl_io, OPENSSL_IOSTREAM_SYNC_TYPE_WRITE);
			else {
				/* have to implement own error handling here to
				   avoid losing actual error. */
				int err = SSL_get_error(ssl_io->ssl, ret);
				/* still need to do this even if it fails,
				   otherwise the outgoing message does not get sent. */
				openssl_iostream_bio_sync(ssl_io, OPENSSL_IOSTREAM_SYNC_TYPE_WRITE);
				/* these are not really errors, don't log */
				if (err == SSL_ERROR_WANT_READ ||
				    err == SSL_ERROR_WANT_WRITE ||
				    err == SSL_ERROR_WANT_ASYNC)
					continue;
				if (openssl_iostream_handle_error(ssl_io, ret, OPENSSL_IOSTREAM_SYNC_TYPE_WRITE,
							      "SSL_shutdown()") < 0) {
					e_debug(ssl_io->event, "%s",
						ssl_io->last_error);
				}
				break;
			}
		}
	}

	/* clear any errors */
	openssl_iostream_clear_errors();

	/* close the plain i/o streams, because their fd may be closed soon,
	   but we may still keep this ssl-iostream referenced until later. */
	i_stream_close(ssl_io->plain_input);
	o_stream_close(ssl_io->plain_output);
}

static void openssl_iostream_destroy(struct ssl_iostream *ssl_io)
{
	openssl_iostream_shutdown(ssl_io);
	ssl_iostream_unref(&ssl_io);
}

static int openssl_iostream_bio_output_real(struct ssl_iostream *ssl_io)
{
	size_t bytes, max_bytes = 0;
	ssize_t sent;
	unsigned char buffer[IO_BLOCK_SIZE];
	int result = 0;
	int ret;

	o_stream_cork(ssl_io->plain_output);
	while ((bytes = BIO_ctrl_pending(ssl_io->bio_ext)) > 0) {
		/* bytes contains how many SSL encrypted bytes we should be
		   sending out */
		max_bytes = o_stream_get_buffer_avail_size(ssl_io->plain_output);
		if (bytes > max_bytes) {
			if (max_bytes == 0) {
				/* wait until output buffer clears */
				break;
			}
			bytes = max_bytes;
		}
		if (bytes > sizeof(buffer))
			bytes = sizeof(buffer);

		/* BIO_read() is guaranteed to return all the bytes that
		   BIO_ctrl_pending() returned */
		ret = BIO_read(ssl_io->bio_ext, buffer, bytes);
		i_assert(ret == (int)bytes);

		/* we limited number of read bytes to plain_output's
		   available size. this send() is guaranteed to either
		   fully succeed or completely fail due to some error. */
		sent = o_stream_send(ssl_io->plain_output, buffer, bytes);
		if (sent < 0) {
			o_stream_uncork(ssl_io->plain_output);
			return -1;
		}
		i_assert(sent == (ssize_t)bytes);
		result = 1;
	}

	ret = o_stream_uncork_flush(ssl_io->plain_output);
	if (ret < 0)
		return -1;
	if (ret == 0 || (bytes > 0 && max_bytes == 0))
		o_stream_set_flush_pending(ssl_io->plain_output, TRUE);

	return result;
}

static int openssl_iostream_bio_output(struct ssl_iostream *ssl_io)
{
	int ret;

	ret = openssl_iostream_bio_output_real(ssl_io);
	if (ret < 0) {
		i_assert(ssl_io->plain_output->stream_errno != 0);
		i_free(ssl_io->plain_stream_errstr);
		ssl_io->plain_stream_errstr =
			i_strdup(o_stream_get_error(ssl_io->plain_output));
		ssl_io->plain_stream_errno =
			ssl_io->plain_output->stream_errno;
		ssl_io->closed = TRUE;
	}
	return ret;
}

static ssize_t
openssl_iostream_read_more(struct ssl_iostream *ssl_io,
			   enum openssl_iostream_sync_type type, size_t wanted,
			   const unsigned char **data_r, size_t *size_r)
{
	*data_r = i_stream_get_data(ssl_io->plain_input, size_r);
	if (*size_r > 0)
		return 0;

	if (type == OPENSSL_IOSTREAM_SYNC_TYPE_CONTINUE_READ) {
		/* only the first i_stream_read() call attempts to read more
		   input. the following reads will just process the buffered
		   data. */
		return 0;
	}

	if (i_stream_read_limited(ssl_io->plain_input, data_r, size_r,
				  wanted) < 0)
		return -1;
	return 0;
}

static int
openssl_iostream_bio_input(struct ssl_iostream *ssl_io,
			   enum openssl_iostream_sync_type type)
{
	const unsigned char *data;
	size_t bytes, size;
	int ret;
	bool bytes_read = FALSE;

	while ((bytes = BIO_ctrl_get_write_guarantee(ssl_io->bio_ext)) > 0) {
		/* bytes contains how many bytes we can write to bio_ext */
		ret = openssl_iostream_read_more(ssl_io, type, bytes,
						 &data, &size);
		if (ret == -1 && size == 0 && !bytes_read) {
			if (ssl_io->plain_input->stream_errno != 0) {
				i_free(ssl_io->plain_stream_errstr);
				ssl_io->plain_stream_errstr =
					i_strdup(i_stream_get_error(ssl_io->plain_input));
				ssl_io->plain_stream_errno =
					ssl_io->plain_input->stream_errno;
			}
			ssl_io->closed = TRUE;
			return -1;
		}
		if (size == 0) {
			/* wait for more input */
			break;
		}
		if (size > bytes)
			size = bytes;

		ret = BIO_write(ssl_io->bio_ext, data, size);
		i_assert(ret == (ssize_t)size);

		i_stream_skip(ssl_io->plain_input, size);
		bytes_read = TRUE;
	}
	if (bytes == 0 && !bytes_read && ssl_io->want_read) {
		/* shouldn't happen */
		e_error(ssl_io->event, "SSL BIO buffer size too small");
		i_free(ssl_io->plain_stream_errstr);
		ssl_io->plain_stream_errstr =
			i_strdup("SSL BIO buffer size too small");
		ssl_io->plain_stream_errno = EINVAL;
		ssl_io->closed = TRUE;
		return -1;
	}
	if (bytes_read) {
		if (ssl_io->ostream_flush_waiting_input) {
			ssl_io->ostream_flush_waiting_input = FALSE;
			o_stream_set_flush_pending(ssl_io->plain_output, TRUE);
		}
	}
	if (bytes_read || i_stream_get_data_size(ssl_io->plain_input) > 0) {
		if (i_stream_get_data_size(ssl_io->plain_input) > 0 ||
		    type != OPENSSL_IOSTREAM_SYNC_TYPE_CONTINUE_READ)
			i_stream_set_input_pending(ssl_io->ssl_input, TRUE);
		ssl_io->want_read = FALSE;
	}
	return (bytes_read ? 1 : 0);
}

int openssl_iostream_bio_sync(struct ssl_iostream *ssl_io,
			      enum openssl_iostream_sync_type type)
{
	int ret;

	i_assert(type != OPENSSL_IOSTREAM_SYNC_TYPE_NONE);

	ret = openssl_iostream_bio_output(ssl_io);
	if (ret >= 0 && openssl_iostream_bio_input(ssl_io, type) > 0)
		ret = 1;
	return ret;
}

static void openssl_iostream_closed(struct ssl_iostream *ssl_io)
{
	if (ssl_io->plain_stream_errno != 0) {
		i_assert(ssl_io->plain_stream_errstr != NULL);
		openssl_iostream_set_error(ssl_io, ssl_io->plain_stream_errstr);
		errno = ssl_io->plain_stream_errno;
	} else {
		openssl_iostream_set_error(ssl_io, "Connection closed");
		errno = EPIPE;
	}
}

int openssl_iostream_handle_error(struct ssl_iostream *ssl_io, int ret,
				  enum openssl_iostream_sync_type type,
				  const char *func_name)
{
	const char *errstr = NULL;
	bool fallback_error = FALSE;
	int err;

	err = SSL_get_error(ssl_io->ssl, ret);
	switch (err) {
	case SSL_ERROR_WANT_WRITE:
		if (type != OPENSSL_IOSTREAM_SYNC_TYPE_NONE &&
		    openssl_iostream_bio_sync(ssl_io, type) == 0) {
			if (type != OPENSSL_IOSTREAM_SYNC_TYPE_WRITE)
				i_panic("SSL ostream buffer size not unlimited");
			return 0;
		}
		if (ssl_io->closed) {
			openssl_iostream_closed(ssl_io);
			return -1;
		}
		if (type == OPENSSL_IOSTREAM_SYNC_TYPE_NONE)
			return 0;
		return 1;
	case SSL_ERROR_WANT_READ:
		ssl_io->want_read = TRUE;
		if (type != OPENSSL_IOSTREAM_SYNC_TYPE_NONE)
			(void)openssl_iostream_bio_sync(ssl_io, type);
		if (ssl_io->closed) {
			openssl_iostream_closed(ssl_io);
			return -1;
		}
		if (type == OPENSSL_IOSTREAM_SYNC_TYPE_NONE)
			return 0;
		return ssl_io->want_read ? 0 : 1;
	case SSL_ERROR_SYSCALL:
		/* eat up the error queue */
		if (ERR_peek_error() != 0) {
			errstr = openssl_iostream_error();
			errno = EINVAL;
		} else if (ret == 0) {
			/* EOF. */
			errno = EPIPE;
			errstr = "Disconnected";
			break;
		} else if (errno != 0) {
			errstr = strerror(errno);
			fallback_error = TRUE;
		} else {
			/* Seen this at least with v1.1.0l SSL_accept() */
			errstr = "OpenSSL BUG: errno=0";
			errno = EINVAL;
			fallback_error = TRUE;
		}
		errstr = t_strdup_printf("%s syscall failed: %s",
					 func_name, errstr);
		break;
	case SSL_ERROR_ZERO_RETURN:
		/* clean connection closing */
		errno = EPIPE;
		if (ssl_io->handshaked)
			i_free_and_null(ssl_io->last_error);
		else if (ssl_io->last_error == NULL) {
			errstr = "SSL connection closed during handshake";
			break;
		}
		return -1;
	case SSL_ERROR_SSL:
		errstr = t_strdup_printf("%s failed: %s",
					 func_name, openssl_iostream_error());
		errno = EINVAL;
		break;
	default:
		errstr = t_strdup_printf("%s failed: unknown failure %d (%s)",
					 func_name, err,
					 openssl_iostream_error());
		errno = EINVAL;
		break;
	}

	if (ssl_io->last_error != NULL && !ssl_io->last_error_is_fallback) {
		if (fallback_error) {
			/* We already have an error, and this new one doesn't
			   provide anything useful over it. Ignore it. */
			return -1;
		}
		errstr = t_strdup_printf("%s+%s", errstr, ssl_io->last_error);
	}
	openssl_iostream_set_error_full(ssl_io, errstr, fallback_error);
	return -1;
}

static bool
openssl_iostream_cert_match_name(struct ssl_iostream *ssl_io,
				 const char *verify_name, const char **reason_r)
{
	if (!ssl_iostream_has_valid_cert(ssl_io)) {
		*reason_r = "Invalid certificate";
		return FALSE;
	}

	return openssl_cert_match_name(ssl_io->ssl, verify_name, reason_r);
}

static int openssl_iostream_handshake(struct ssl_iostream *ssl_io)
{
	const char *reason, *error = NULL;
	int ret;

	if (ssl_io->handshaked)
		return openssl_iostream_bio_sync(ssl_io, OPENSSL_IOSTREAM_SYNC_TYPE_HANDSHAKE);

	/* we are being destroyed, so do not do any more handshaking */
	if (ssl_io->destroyed) {
		errno = EPIPE;
		return -1;
	}

	if (ssl_io->ctx->client_ctx) {
		while ((ret = SSL_connect(ssl_io->ssl)) <= 0) {
			ret = openssl_iostream_handle_error(ssl_io, ret,
				OPENSSL_IOSTREAM_SYNC_TYPE_HANDSHAKE, "SSL_connect()");
			if (ret < 0)
				ssl_io->do_shutdown = TRUE;
			if (ret <= 0)
				return ret;
		}
	} else {
		while ((ret = SSL_accept(ssl_io->ssl)) <= 0) {
			ret = openssl_iostream_handle_error(ssl_io, ret,
				OPENSSL_IOSTREAM_SYNC_TYPE_HANDSHAKE, "SSL_accept()");
			if (ret < 0)
				ssl_io->do_shutdown = TRUE;
			if (ret <= 0)
				return ret;
		}
	}
	/* handshake finished */
	(void)openssl_iostream_bio_sync(ssl_io, OPENSSL_IOSTREAM_SYNC_TYPE_HANDSHAKE);

	if (ssl_io->handshake_callback != NULL) {
		ssl_io->state = ssl_io->handshake_callback(&error, ssl_io->handshake_context);
		if (ssl_io->state != SSL_IOSTREAM_STATE_OK) {
			i_assert(error != NULL);
			openssl_iostream_set_error(ssl_io, error);
			ssl_io->handshake_failed = TRUE;
		}
	} else if (ssl_io->connected_host != NULL && !ssl_io->handshake_failed &&
		   !ssl_io->allow_invalid_cert) {
		enum ssl_iostream_cert_validity validity =
			ssl_iostream_check_cert_validity(ssl_io,
				ssl_io->connected_host, &reason);
		switch (validity) {
		case SSL_IOSTREAM_CERT_VALIDITY_OK:
			ssl_io->state = SSL_IOSTREAM_STATE_OK;
			break;
		case SSL_IOSTREAM_CERT_VALIDITY_NO_CERT:
		case SSL_IOSTREAM_CERT_VALIDITY_INVALID:
			ssl_io->state = SSL_IOSTREAM_STATE_INVALID_CERT;
			break;
		case SSL_IOSTREAM_CERT_VALIDITY_NAME_MISMATCH:
			ssl_io->state = SSL_IOSTREAM_STATE_NAME_MISMATCH;
			break;
		}
		if (validity != SSL_IOSTREAM_CERT_VALIDITY_OK) {
			openssl_iostream_set_error(ssl_io, reason);
			ssl_io->handshake_failed = TRUE;
		}
	}
	if (ssl_io->handshake_failed) {
		openssl_iostream_shutdown(ssl_io);
		errno = EINVAL;
		return -1;
	}
	i_free_and_null(ssl_io->last_error);
	ssl_io->handshaked = TRUE;
	ssl_io->state = SSL_IOSTREAM_STATE_OK;

	const char *alpn_proto = ssl_iostream_get_application_protocol(ssl_io);
	if (alpn_proto != NULL && *alpn_proto != '\0')
		e_debug(ssl_io->event, "SSL: Chosen application protocol %s", alpn_proto);
	if (ssl_io->ssl_output != NULL)
		(void)o_stream_flush(ssl_io->ssl_output);
	return 1;
}

static void
openssl_iostream_set_handshake_callback(struct ssl_iostream *ssl_io,
					ssl_iostream_handshake_callback_t *callback,
					void *context)
{
	ssl_io->handshake_callback = callback;
	ssl_io->handshake_context = context;
}

static void
openssl_iostream_set_sni_callback(struct ssl_iostream *ssl_io,
				  ssl_iostream_sni_callback_t *callback,
				  void *context)
{
	ssl_io->sni_callback = callback;
	ssl_io->sni_context = context;
}

static void
openssl_iostream_change_context(struct ssl_iostream *ssl_io,
				struct ssl_iostream_context *ctx)
{
	if (ctx != ssl_io->ctx) {
		SSL_set_SSL_CTX(ssl_io->ssl, ctx->ssl_ctx);
		ssl_iostream_context_ref(ctx);
		ssl_iostream_context_unref(&ssl_io->ctx);
		ssl_io->ctx = ctx;
	}
}

static void openssl_iostream_set_log_prefix(struct ssl_iostream *ssl_io,
					    const char *prefix)
{
	event_set_append_log_prefix(ssl_io->event, prefix);
}

static enum ssl_iostream_state
openssl_iostream_get_state(const struct ssl_iostream *ssl_io)
{
	return ssl_io->state;
}

static enum ssl_iostream_cert_validity
openssl_iostream_get_cert_validity(const struct ssl_iostream *ssl_io)
{
	if (!ssl_io->cert_received)
		return SSL_IOSTREAM_CERT_VALIDITY_NO_CERT;
	if (ssl_io->cert_broken)
		return SSL_IOSTREAM_CERT_VALIDITY_INVALID;
	return SSL_IOSTREAM_CERT_VALIDITY_OK;
}

static bool
openssl_iostream_get_allow_invalid_cert(struct ssl_iostream *ssl_io)
{
	return ssl_io->allow_invalid_cert;
}

static const char *
openssl_iostream_get_peer_username(struct ssl_iostream *ssl_io)
{
	X509 *x509;
	char *name;
	int len;

	if (!ssl_iostream_has_valid_cert(ssl_io))
		return NULL;

#ifdef HAVE_SSL_get1_peer_certificate
	x509 = SSL_get1_peer_certificate(ssl_io->ssl);
#else
	x509 = SSL_get_peer_certificate(ssl_io->ssl);
#endif
	i_assert(x509 != NULL);

	len = X509_NAME_get_text_by_NID(X509_get_subject_name(x509),
					ssl_io->ctx->username_nid, NULL, 0);
	if (len < 0)
		name = NULL;
	else {
		name = t_malloc0(len + 1);
		if (X509_NAME_get_text_by_NID(X509_get_subject_name(x509),
					      ssl_io->ctx->username_nid,
					      name, len + 1) < 0)
			name = NULL;
		else if (strlen(name) != (size_t)len) {
			/* NUL characters in name. Someone's trying to fake
			   being another user? Don't allow it. */
			name = NULL;
		}
	}
	X509_free(x509);

	return name;
}

static const char *openssl_iostream_get_server_name(struct ssl_iostream *ssl_io)
{
	return ssl_io->sni_host;
}

static const char *
openssl_iostream_get_compression(struct ssl_iostream *ssl_io)
{
#if !defined(OPENSSL_NO_COMP)
	const COMP_METHOD *comp;

	comp = SSL_get_current_compression(ssl_io->ssl);
	return comp == NULL ? NULL : SSL_COMP_get_name(comp);
#else
	return NULL;
#endif
}

static const char *
openssl_iostream_get_security_string(struct ssl_iostream *ssl_io)
{
	const SSL_CIPHER *cipher;
#if !defined(OPENSSL_NO_COMP)
	const COMP_METHOD *comp;
#endif
	const char *comp_str;
	int bits, alg_bits;

	if (!ssl_io->handshaked)
		return NULL;

	cipher = SSL_get_current_cipher(ssl_io->ssl);
	bits = SSL_CIPHER_get_bits(cipher, &alg_bits);
#if !defined(OPENSSL_NO_COMP)
	comp = SSL_get_current_compression(ssl_io->ssl);
	comp_str = comp == NULL ? "" :
		t_strconcat(" ", SSL_COMP_get_name(comp), NULL);
#else
	comp_str = "";
#endif
	return t_strdup_printf("%s with cipher %s (%d/%d bits)%s",
			       SSL_get_version(ssl_io->ssl),
			       SSL_CIPHER_get_name(cipher),
			       bits, alg_bits, comp_str);
}

static const char *
openssl_iostream_get_last_error(struct ssl_iostream *ssl_io)
{
	return ssl_io->last_error;
}

static const char *
openssl_iostream_get_cipher(struct ssl_iostream *ssl_io, unsigned int *bits_r)
{
	if (!ssl_io->handshaked)
		return NULL;

	const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl_io->ssl);
	*bits_r = SSL_CIPHER_get_bits(cipher, NULL);
	return SSL_CIPHER_get_name(cipher);
}

static const char *
openssl_iostream_get_pfs(struct ssl_iostream *ssl_io)
{
	if (!ssl_io->handshaked)
		return NULL;

	const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl_io->ssl);
	int nid = SSL_CIPHER_get_kx_nid(cipher);
	return OBJ_nid2sn(nid);
}

static const char *
openssl_iostream_get_protocol_name(struct ssl_iostream *ssl_io)
{
	if (!ssl_io->handshaked)
		return NULL;
	return SSL_get_version(ssl_io->ssl);
}

static enum ssl_iostream_protocol_version
openssl_iostream_get_protocol_version(struct ssl_iostream *ssl_io)
{
	if (!ssl_io->handshaked)
		return SSL_IOSTREAM_PROTOCOL_VERSION_UNKNOWN;

	int version = SSL_version(ssl_io->ssl);

	switch (version) {
	case SSL3_VERSION:
		return SSL_IOSTREAM_PROTOCOL_VERSION_SSL3;
	case TLS1_VERSION:
		return SSL_IOSTREAM_PROTOCOL_VERSION_TLS1;
	case TLS1_1_VERSION:
		return SSL_IOSTREAM_PROTOCOL_VERSION_TLS1_1;
	case TLS1_2_VERSION:
		return SSL_IOSTREAM_PROTOCOL_VERSION_TLS1_2;
	case TLS1_3_VERSION:
		return SSL_IOSTREAM_PROTOCOL_VERSION_TLS1_3;
	default:
		break;
	}
	i_assert(version > TLS1_3_VERSION);
	return SSL_IOSTREAM_PROTOCOL_VERSION_NEW;
}

static const char *
openssl_iostream_get_ja3(struct ssl_iostream *ssl_io)
{
	if (!ssl_io->handshaked)
		return NULL;
	return ssl_io->ja3_str;
}

static const char *
openssl_iostream_get_application_protocol(struct ssl_iostream *ssl_io)
{
	if (!ssl_io->handshaked || ssl_io->handshake_failed)
		return NULL;
	const unsigned char *data;
	unsigned int len;

	SSL_get0_alpn_selected(ssl_io->ssl, &data, &len);
	if (data != NULL)
		return t_strndup(data, len);
	return NULL;
}

static int
openssl_iostream_get_cb_tls_exporter(struct ssl_iostream *ssl_io,
				     const buffer_t **data_r,
				     const char **error_r)
{
	/* RFC 9266, Section 4.2:

	   When TLS renegotiation is enabled on a connection, the "tls-exporter"
	   channel binding type is not defined for that connection, and
	   implementations MUST NOT support it.
	 */
	if (SSL_version(ssl_io->ssl) < TLS1_3_VERSION
#ifdef SSL_OP_NO_RENEGOTIATION
	    && HAS_NO_BITS(SSL_get_options(ssl_io->ssl),
			   SSL_OP_NO_RENEGOTIATION))
#endif
	{
		*error_r = t_strdup_printf(
			"Channel binding type 'tls-exporter' not available: "
			"TLS renegotiation is enabled for %s",
			SSL_get_version(ssl_io->ssl));
		return -1;
	}

	static const char literal[] = "EXPORTER-Channel-Binding";
	static const size_t size = 32;
	buffer_t *buf = t_buffer_create(size);
	void *data = buffer_get_space_unsafe(buf, 0, size);

	if (SSL_export_keying_material(ssl_io->ssl, data, size,
				       literal, sizeof(literal) - 1,
				       NULL, 0, 0) != 1) {
		*error_r = t_strdup_printf(
			"Failed to compose channel binding 'tls-exporter': %s",
			openssl_iostream_error());
		return -1;
	}

        *data_r = buf;
	return 0;
}

static int
openssl_iostream_get_cb_tls_unique(struct ssl_iostream *ssl_io,
				   const buffer_t **data_r,
				   const char **error_r)
{
	/* RFC 9266, Section 3:

	   The specifications for Salted Challenge Response Authentication
	   Mechanism (SCRAM) [RFC5802] [RFC7677] and Generic Security Service
	   Application Program Interface (GSS-API) over Simple Authentication
	   and Security Layer (SASL) [RFC5801] define "tls-unique" as the
	   default channel binding to use over TLS.  As "tls-unique" is not
	   defined for TLS 1.3 (and greater), this document updates [RFC5801],
	   [RFC5802], and [RFC7677] to use "tls-exporter" as the default channel
	   binding over TLS 1.3 (and greater).
	 */
	if (SSL_version(ssl_io->ssl) >= TLS1_3_VERSION) {
		*error_r = t_strdup_printf(
			"Channel binding type 'tls-unique' not defined: "
			"TLS version is %s", SSL_get_version(ssl_io->ssl));
		return -1;
	}

	static const size_t max_size = EVP_MAX_MD_SIZE;
	buffer_t *buf = t_buffer_create(max_size);
	void *data = buffer_get_space_unsafe(buf, 0, max_size);
	size_t size;
	bool peer_finished;

	/* Roles are reversed when session reuse is in effect */
	peer_finished = !ssl_io->ctx->client_ctx;
	if (SSL_session_reused(ssl_io->ssl) != 0)
		peer_finished = !peer_finished;
	if (peer_finished)
		size = SSL_get_peer_finished(ssl_io->ssl, data, max_size);
	else
		size = SSL_get_finished(ssl_io->ssl, data, max_size);

	buffer_set_used_size(buf, size);

	*data_r = buf;
	return 0;
}

static int
openssl_iostream_get_channel_binding(struct ssl_iostream *ssl_io,
				     const char *type, const buffer_t **data_r,
				     const char **error_r)
{
	*error_r = NULL;
	*data_r = NULL;

	if (!ssl_io->handshaked) {
		*error_r = "Channel binding not available before handshake";
		return -1;
	}

	if (strcmp(type, SSL_CHANNEL_BIND_TYPE_TLS_UNIQUE) == 0) {
		return openssl_iostream_get_cb_tls_unique(
			ssl_io, data_r, error_r);
	} else if (strcmp(type, SSL_CHANNEL_BIND_TYPE_TLS_EXPORTER) == 0) {
		return openssl_iostream_get_cb_tls_exporter(
			ssl_io, data_r, error_r);
	}

	*error_r = t_strdup_printf(
		"Unsupported channel binding type '%s'", type);
	return -1;
}

static int
openssl_iostream_get_peer_cert_fingerprint(struct ssl_iostream *ssl_io,
					   const char **cert_fp_r,
					   const char **pubkey_fp_r,
					   const char **error_r)
{
	SSL *ssl = ssl_io->ssl;
	struct ssl_iostream_context *ctx = ssl_io->ctx;
	const char *cert_fp;

	if (!ssl_io->handshaked || ssl_io->handshake_failed)
		return 0;

	/* Use cached result */
	if (ssl_io->cert_fp != NULL) {
		*cert_fp_r = ssl_io->cert_fp;
		*pubkey_fp_r = ssl_io->pubkey_fp;
		return 1;
	}

#ifdef HAVE_SSL_get1_peer_certificate
	X509 *cert = SSL_get0_peer_certificate(ssl);
#else
	X509 *cert = SSL_get_peer_certificate(ssl);
#endif
	if (cert == NULL)
		return 0;

	if (ctx->pcert_fp_algo == NULL) {
		*error_r = "No hash algorithm configured";
		return -1;
	}

	unsigned int fp_len = EVP_MAX_MD_SIZE;
	unsigned char result[EVP_MAX_MD_SIZE];

	if (X509_digest(cert, ctx->pcert_fp_algo, result, &fp_len) == 0) {
		*error_r = openssl_iostream_error();
		return -1;
	}

	cert_fp = binary_to_hex(result, fp_len);

	fp_len = EVP_MAX_MD_SIZE;
	memset(result, 0, EVP_MAX_MD_SIZE);

	/* Apparently X509_pubkey_digest does not work correctly,
	   so we need to do this the hard way. */
	BIO *bio = BIO_new(BIO_s_null());
	BIO *hash = BIO_new(BIO_f_md());
	BIO_set_md(hash, ctx->pcert_fp_algo);
	bio = BIO_push(hash, bio);

	EVP_PKEY *pubkey = X509_get0_pubkey(cert);
	int ret = i2d_PUBKEY_bio(bio, pubkey);

	if (ret == 1)
		fp_len = BIO_gets(hash, (void*)result, EVP_MAX_MD_SIZE);
	else
		*error_r = openssl_iostream_error();

	BIO_free_all(bio);

	if (ret == 0)
		return -1;

	ssl_io->cert_fp = i_strdup(cert_fp);
	ssl_io->pubkey_fp = i_strdup(binary_to_hex(result, fp_len));
	*cert_fp_r = ssl_io->cert_fp;
	*pubkey_fp_r = ssl_io->pubkey_fp;

	return 1;
}


static const struct iostream_ssl_vfuncs ssl_vfuncs = {
	.global_init = openssl_iostream_global_init,
	.context_init_client = openssl_iostream_context_init_client,
	.context_init_server = openssl_iostream_context_init_server,
	.context_ref = openssl_iostream_context_ref,
	.context_unref = openssl_iostream_context_unref,

	.create = openssl_iostream_create,
	.unref = openssl_iostream_unref,
	.destroy = openssl_iostream_destroy,

	.handshake = openssl_iostream_handshake,
	.set_handshake_callback = openssl_iostream_set_handshake_callback,
	.set_sni_callback = openssl_iostream_set_sni_callback,
	.change_context = openssl_iostream_change_context,

	.set_log_prefix = openssl_iostream_set_log_prefix,
	.get_state = openssl_iostream_get_state,
	.get_cert_validity = openssl_iostream_get_cert_validity,
	.cert_match_name = openssl_iostream_cert_match_name,
	.get_allow_invalid_cert = openssl_iostream_get_allow_invalid_cert,
	.get_peer_username = openssl_iostream_get_peer_username,
	.get_server_name = openssl_iostream_get_server_name,
	.get_compression = openssl_iostream_get_compression,
	.get_security_string = openssl_iostream_get_security_string,
	.get_last_error = openssl_iostream_get_last_error,
	.get_cipher = openssl_iostream_get_cipher,
	.get_pfs = openssl_iostream_get_pfs,
	.get_protocol_name = openssl_iostream_get_protocol_name,
	.get_protocol_version = openssl_iostream_get_protocol_version,
	.get_ja3 = openssl_iostream_get_ja3,

	.get_application_protocol = openssl_iostream_get_application_protocol,
	.set_application_protocols = openssl_iostream_context_set_application_protocols,

	.get_channel_binding = openssl_iostream_get_channel_binding,
	.get_peer_cert_fingerprint = openssl_iostream_get_peer_cert_fingerprint,
};

void ssl_iostream_openssl_init(void)
{
	unsigned char buf;
	if (RAND_bytes(&buf, 1) < 1)
		i_fatal("OpenSSL RNG failed to initialize");
	iostream_ssl_module_init(&ssl_vfuncs);
}

void ssl_iostream_openssl_deinit(void)
{
	openssl_iostream_global_deinit();
}
