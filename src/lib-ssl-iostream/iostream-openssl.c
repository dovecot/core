/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "ostream-private.h"
#include "iostream-openssl.h"

#include <openssl/rand.h>
#include <openssl/err.h>

static void openssl_iostream_free(struct ssl_iostream *ssl_io);

void openssl_iostream_set_error(struct ssl_iostream *ssl_io, const char *str)
{
	char *new_str;

	/* i_debug() may sometimes be overriden, making it write to this very
	   same SSL stream, in which case the provided str may be invalidated
	   before it is even used. Therefore, we duplicate it immediately. */
	new_str = i_strdup(str);

	if (ssl_io->verbose) {
		/* This error should normally be logged by lib-ssl-iostream's
		   caller. But if verbose=TRUE, log it here as well to make
		   sure that the error is always logged. */
		i_debug("%sSSL error: %s", ssl_io->log_prefix, new_str);
	}
	i_free(ssl_io->last_error);
	ssl_io->last_error = new_str;
}

static void openssl_info_callback(const SSL *ssl, int where, int ret)
{
	struct ssl_iostream *ssl_io;

	ssl_io = SSL_get_ex_data(ssl, dovecot_ssl_extdata_index);
	if ((where & SSL_CB_ALERT) != 0) {
		switch (ret & 0xff) {
		case SSL_AD_CLOSE_NOTIFY:
			i_debug("%sSSL alert: %s",
				ssl_io->log_prefix,
				SSL_alert_desc_string_long(ret));
			break;
		default:
			i_debug("%sSSL alert: where=0x%x, ret=%d: %s %s",
				ssl_io->log_prefix, where, ret,
				SSL_alert_type_string_long(ret),
				SSL_alert_desc_string_long(ret));
			break;
		}
	} else if (ret == 0) {
		i_debug("%sSSL failed: where=0x%x: %s",
			ssl_io->log_prefix, where, SSL_state_string_long(ssl));
	} else {
		i_debug("%sSSL: where=0x%x, ret=%d: %s",
			ssl_io->log_prefix, where, ret,
			SSL_state_string_long(ssl));
	}
}

static int
openssl_iostream_use_certificate(struct ssl_iostream *ssl_io, const char *cert,
				 const char **error_r)
{
	BIO *in;
	X509 *x;
	int ret = 0;

	in = BIO_new_mem_buf(t_strdup_noconst(cert), strlen(cert));
	if (in == NULL) {
		*error_r = t_strdup_printf("BIO_new_mem_buf() failed: %s",
					   openssl_iostream_error());
		return -1;
	}

	x = PEM_read_bio_X509(in, NULL, NULL, NULL);
	if (x != NULL) {
		ret = SSL_use_certificate(ssl_io->ssl, x);
		if (ERR_peek_error() != 0)
			ret = 0;
		X509_free(x);
	}
	BIO_free(in);

	if (ret == 0) {
		*error_r = t_strdup_printf("Can't load ssl_cert: %s",
			openssl_iostream_use_certificate_error(cert, NULL));
		return -1;
	}
	return 0;
}

static int
openssl_iostream_use_key(struct ssl_iostream *ssl_io,
			 const struct ssl_iostream_cert *set,
			 const char **error_r)
{
	EVP_PKEY *pkey;
	int ret = 0;

	if (openssl_iostream_load_key(set, &pkey, error_r) < 0)
		return -1;
	if (SSL_use_PrivateKey(ssl_io->ssl, pkey) != 1) {
		*error_r = t_strdup_printf("Can't load SSL private key: %s",
					   openssl_iostream_key_load_error());
		ret = -1;
	}
	EVP_PKEY_free(pkey);
	return ret;
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
				"ssl_ca setting?"));
		if (ssl_io->verbose_invalid_cert)
			i_info("%s", ssl_io->last_error);
	} else if (ssl_io->verbose) {
		i_info("Received valid SSL certificate: %s", certname);
	}
	if (preverify_ok == 0) {
		ssl_io->cert_broken = TRUE;
		if (!ssl_io->allow_invalid_cert) {
			ssl_io->handshake_failed = TRUE;
			return 0;
		}
	}
	return 1;
}

static int
openssl_iostream_set(struct ssl_iostream *ssl_io,
		     const struct ssl_iostream_settings *set,
		     const char **error_r)
{
	const struct ssl_iostream_settings *ctx_set = &ssl_io->ctx->set;
	int verify_flags;

	if (set->verbose)
		SSL_set_info_callback(ssl_io->ssl, openssl_info_callback);

       if (set->cipher_list != NULL &&
	    strcmp(ctx_set->cipher_list, set->cipher_list) != 0) {
		if (SSL_set_cipher_list(ssl_io->ssl, set->cipher_list) == 0) {
			*error_r = t_strdup_printf(
				"Can't set cipher list to '%s': %s",
				set->cipher_list, openssl_iostream_error());
			return -1;
		}
	}
#ifdef HAVE_SSL_CTX_SET1_CURVES_LIST
	if (set->curve_list != NULL && strlen(set->curve_list) > 0 &&
		(ctx_set->curve_list == NULL || strcmp(ctx_set->curve_list, set->curve_list) != 0)) {
		if (SSL_set1_curves_list(ssl_io->ssl, set->curve_list) == 0) {
			*error_r = t_strdup_printf(
					"Failed to set curve list to '%s'",
					set->curve_list);
			return -1;
		}
	}
#endif
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
        if (set->ciphersuites != NULL &&
	    strcmp(ctx_set->ciphersuites, set->ciphersuites) != 0) {
		if (SSL_set_ciphersuites(ssl_io->ssl, set->ciphersuites) == 0) {
			*error_r = t_strdup_printf(
				"Can't set ciphersuites to '%s': %s",
				set->ciphersuites, openssl_iostream_error());
			return -1;
		}
	}
#endif
	if (set->prefer_server_ciphers)
		SSL_set_options(ssl_io->ssl, SSL_OP_CIPHER_SERVER_PREFERENCE);
	if (set->min_protocol != NULL) {
#if defined(HAVE_SSL_CLEAR_OPTIONS)
		SSL_clear_options(ssl_io->ssl, OPENSSL_ALL_PROTOCOL_OPTIONS);
#endif
		long opts;
		int min_protocol;
		if (openssl_min_protocol_to_options(set->min_protocol, &opts,
						    &min_protocol) < 0) {
			*error_r = t_strdup_printf(
					"Unknown ssl_min_protocol setting '%s'",
					set->min_protocol);
			return -1;
		}
#ifdef HAVE_SSL_CTX_SET_MIN_PROTO_VERSION
		SSL_set_min_proto_version(ssl_io->ssl, min_protocol);
#else
		SSL_set_options(ssl_io->ssl, opts);
#endif
	}

	if (set->cert.cert != NULL && strcmp(ctx_set->cert.cert, set->cert.cert) != 0) {
		if (openssl_iostream_use_certificate(ssl_io, set->cert.cert, error_r) < 0)
			return -1;
	}
	if (set->cert.key != NULL && strcmp(ctx_set->cert.key, set->cert.key) != 0) {
		if (openssl_iostream_use_key(ssl_io, &set->cert, error_r) < 0)
			return -1;
	}
	if (set->alt_cert.cert != NULL && strcmp(ctx_set->alt_cert.cert, set->alt_cert.cert) != 0) {
		if (openssl_iostream_use_certificate(ssl_io, set->alt_cert.cert, error_r) < 0)
			return -1;
	}
	if (set->alt_cert.key != NULL && strcmp(ctx_set->alt_cert.key, set->alt_cert.key) != 0) {
		if (openssl_iostream_use_key(ssl_io, &set->alt_cert, error_r) < 0)
			return -1;
	}
	if (set->verify_remote_cert) {
		if (ssl_io->ctx->client_ctx)
			verify_flags = SSL_VERIFY_NONE;
		else
			verify_flags = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
		SSL_set_verify(ssl_io->ssl, verify_flags,
			       openssl_iostream_verify_client_cert);
	}

	if (set->cert_username_field != NULL) {
		ssl_io->username_nid = OBJ_txt2nid(set->cert_username_field);
		if (ssl_io->username_nid == NID_undef) {
			*error_r = t_strdup_printf(
				"Invalid cert_username_field: %s",
				set->cert_username_field);
			return -1;
		}
	} else {
		ssl_io->username_nid = ssl_io->ctx->username_nid;
	}

	ssl_io->verbose = set->verbose;
	ssl_io->verbose_invalid_cert = set->verbose_invalid_cert || set->verbose;
	ssl_io->allow_invalid_cert = set->allow_invalid_cert;
	return 0;
}

static int
openssl_iostream_create(struct ssl_iostream_context *ctx, const char *host,
			const struct ssl_iostream_settings *set,
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
	ssl_io->log_prefix = host == NULL ? i_strdup("") :
		i_strdup_printf("%s: ", host);
	/* bio_int will be freed by SSL_free() */
	SSL_set_bio(ssl_io->ssl, bio_int, bio_int);
        SSL_set_ex_data(ssl_io->ssl, dovecot_ssl_extdata_index, ssl_io);
#ifdef HAVE_SSL_GET_SERVERNAME
	SSL_set_tlsext_host_name(ssl_io->ssl, host);
#endif

	if (openssl_iostream_set(ssl_io, set, error_r) < 0) {
		openssl_iostream_free(ssl_io);
		return -1;
	}

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
	i_free(ssl_io->plain_stream_errstr);
	i_free(ssl_io->last_error);
	i_free(ssl_io->connected_host);
	i_free(ssl_io->sni_host);
	i_free(ssl_io->log_prefix);
	i_free(ssl_io);
}

static void openssl_iostream_unref(struct ssl_iostream *ssl_io)
{
	i_assert(ssl_io->refcount > 0);
	if (--ssl_io->refcount > 0)
		return;

	openssl_iostream_free(ssl_io);
}

void openssl_iostream_shutdown(struct ssl_iostream *ssl_io)
{
	if (ssl_io->destroyed)
		return;

	i_assert(ssl_io->ssl_input != NULL);
	i_assert(ssl_io->ssl_output != NULL);

	ssl_io->destroyed = TRUE;
	if (ssl_io->handshaked && SSL_shutdown(ssl_io->ssl) != 1) {
		/* if bidirectional shutdown fails we need to clear
		   the error queue */
		openssl_iostream_clear_errors();
	}
	(void)openssl_iostream_more(ssl_io, OPENSSL_IOSTREAM_SYNC_TYPE_WRITE);
	(void)o_stream_flush(ssl_io->plain_output);
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

static bool openssl_iostream_bio_output(struct ssl_iostream *ssl_io)
{
	size_t bytes, max_bytes;
	ssize_t sent;
	unsigned char buffer[IO_BLOCK_SIZE];
	bool bytes_sent = FALSE;
	int ret;

	o_stream_cork(ssl_io->plain_output);
	while ((bytes = BIO_ctrl_pending(ssl_io->bio_ext)) > 0) {
		/* bytes contains how many SSL encrypted bytes we should be
		   sending out */
		max_bytes = o_stream_get_buffer_avail_size(ssl_io->plain_output);
		if (bytes > max_bytes) {
			if (max_bytes == 0) {
				/* wait until output buffer clears */
				o_stream_set_flush_pending(ssl_io->plain_output,
							   TRUE);
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
			i_assert(ssl_io->plain_output->stream_errno != 0);
			i_free(ssl_io->plain_stream_errstr);
			ssl_io->plain_stream_errstr =
				i_strdup(o_stream_get_error(ssl_io->plain_output));
			ssl_io->plain_stream_errno =
				ssl_io->plain_output->stream_errno;
			ssl_io->closed = TRUE;
			break;
		}
		i_assert(sent == (ssize_t)bytes);
		bytes_sent = TRUE;
	}
	o_stream_uncork(ssl_io->plain_output);
	return bytes_sent;
}

static ssize_t
openssl_iostream_read_more(struct ssl_iostream *ssl_io,
			   enum openssl_iostream_sync_type type,
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

	if (i_stream_read_more(ssl_io->plain_input, data_r, size_r) < 0)
		return -1;
	return 0;
}

static bool openssl_iostream_bio_input(struct ssl_iostream *ssl_io,
				       enum openssl_iostream_sync_type type)
{
	const unsigned char *data;
	size_t bytes, size;
	int ret;
	bool bytes_read = FALSE;

	while ((bytes = BIO_ctrl_get_write_guarantee(ssl_io->bio_ext)) > 0) {
		/* bytes contains how many bytes we can write to bio_ext */
		ssl_io->plain_input->real_stream->try_alloc_limit = bytes;
		ret = openssl_iostream_read_more(ssl_io, type, &data, &size);
		ssl_io->plain_input->real_stream->try_alloc_limit = 0;
		if (ret == -1 && size == 0 && !bytes_read) {
			if (ssl_io->plain_input->stream_errno != 0) {
				i_free(ssl_io->plain_stream_errstr);
				ssl_io->plain_stream_errstr =
					i_strdup(i_stream_get_error(ssl_io->plain_input));
				ssl_io->plain_stream_errno =
					ssl_io->plain_input->stream_errno;
			}
			ssl_io->closed = TRUE;
			return FALSE;
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
		i_error("SSL BIO buffer size too small");
		i_free(ssl_io->plain_stream_errstr);
		ssl_io->plain_stream_errstr =
			i_strdup("SSL BIO buffer size too small");
		ssl_io->plain_stream_errno = EINVAL;
		ssl_io->closed = TRUE;
		return FALSE;
	}
	if (i_stream_get_data_size(ssl_io->plain_input) > 0) {
		i_error("SSL: Too much data in buffered plain input buffer");
		i_free(ssl_io->plain_stream_errstr);
		ssl_io->plain_stream_errstr =
			i_strdup("SSL: Too much data in buffered plain input buffer");
		ssl_io->plain_stream_errno = EINVAL;
		ssl_io->closed = TRUE;
		return FALSE;
	}
	if (bytes_read) {
		if (ssl_io->ostream_flush_waiting_input) {
			ssl_io->ostream_flush_waiting_input = FALSE;
			o_stream_set_flush_pending(ssl_io->plain_output, TRUE);
		}
		if (type != OPENSSL_IOSTREAM_SYNC_TYPE_FIRST_READ &&
		    type != OPENSSL_IOSTREAM_SYNC_TYPE_CONTINUE_READ)
			i_stream_set_input_pending(ssl_io->ssl_input, TRUE);
		ssl_io->want_read = FALSE;
	}
	return bytes_read;
}

bool openssl_iostream_bio_sync(struct ssl_iostream *ssl_io,
			       enum openssl_iostream_sync_type type)
{
	bool ret;

	ret = openssl_iostream_bio_output(ssl_io);
	if (openssl_iostream_bio_input(ssl_io, type))
		ret = TRUE;
	return ret;
}

int openssl_iostream_more(struct ssl_iostream *ssl_io,
			  enum openssl_iostream_sync_type type)
{
	int ret;

	if (!ssl_io->handshaked) {
		if ((ret = ssl_iostream_handshake(ssl_io)) <= 0)
			return ret;
	}
	(void)openssl_iostream_bio_sync(ssl_io, type);
	return 1;
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
	int err;

	err = SSL_get_error(ssl_io->ssl, ret);
	switch (err) {
	case SSL_ERROR_WANT_WRITE:
		if (!openssl_iostream_bio_sync(ssl_io, type)) {
			if (type != OPENSSL_IOSTREAM_SYNC_TYPE_WRITE)
				i_panic("SSL ostream buffer size not unlimited");
			return 0;
		}
		if (ssl_io->closed) {
			openssl_iostream_closed(ssl_io);
			return -1;
		}
		return 1;
	case SSL_ERROR_WANT_READ:
		ssl_io->want_read = TRUE;
		(void)openssl_iostream_bio_sync(ssl_io, type);
		if (ssl_io->closed) {
			openssl_iostream_closed(ssl_io);
			return -1;
		}
		return ssl_io->want_read ? 0 : 1;
	case SSL_ERROR_SYSCALL:
		/* eat up the error queue */
		if (ERR_peek_error() != 0) {
			errstr = openssl_iostream_error();
			errno = EINVAL;
		} else if (ret != 0) {
			i_assert(errno != 0);
			errstr = strerror(errno);
		} else {
			/* EOF. */
			errno = EPIPE;
			errstr = "Disconnected";
			break;
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

	openssl_iostream_set_error(ssl_io, errstr);
	return -1;
}

static bool
openssl_iostream_cert_match_name(struct ssl_iostream *ssl_io,
				 const char *verify_name, const char **reason_r)
{
	if (!ssl_iostream_has_valid_client_cert(ssl_io)) {
		*reason_r = "Invalid certificate";
		return FALSE;
	}

	return openssl_cert_match_name(ssl_io->ssl, verify_name, reason_r);
}

static int openssl_iostream_handshake(struct ssl_iostream *ssl_io)
{
	const char *reason, *error = NULL;
	int ret;

	i_assert(!ssl_io->handshaked);

	/* we are being destroyed, so do not do any more handshaking */
	if (ssl_io->destroyed)
		return 0;

	if (ssl_io->ctx->client_ctx) {
		while ((ret = SSL_connect(ssl_io->ssl)) <= 0) {
			ret = openssl_iostream_handle_error(ssl_io, ret,
				OPENSSL_IOSTREAM_SYNC_TYPE_HANDSHAKE, "SSL_connect()");
			if (ret <= 0)
				return ret;
		}
	} else {
		while ((ret = SSL_accept(ssl_io->ssl)) <= 0) {
			ret = openssl_iostream_handle_error(ssl_io, ret,
				OPENSSL_IOSTREAM_SYNC_TYPE_HANDSHAKE, "SSL_accept()");
			if (ret <= 0)
				return ret;
		}
	}
	/* handshake finished */
	(void)openssl_iostream_bio_sync(ssl_io, OPENSSL_IOSTREAM_SYNC_TYPE_HANDSHAKE);

	if (ssl_io->handshake_callback != NULL) {
		if (ssl_io->handshake_callback(&error, ssl_io->handshake_context) < 0) {
			i_assert(error != NULL);
			openssl_iostream_set_error(ssl_io, error);
			ssl_io->handshake_failed = TRUE;
		}
       } else if (ssl_io->connected_host != NULL && !ssl_io->handshake_failed &&
		  !ssl_io->allow_invalid_cert) {
		if (ssl_iostream_check_cert_validity(ssl_io, ssl_io->connected_host, &reason) < 0) {
			openssl_iostream_set_error(ssl_io, reason);
			ssl_io->handshake_failed = TRUE;
		}
	}
	if (ssl_io->handshake_failed) {
		i_stream_close(ssl_io->plain_input);
		o_stream_close(ssl_io->plain_output);
		errno = EINVAL;
		return -1;
	}
	i_free_and_null(ssl_io->last_error);
	ssl_io->handshaked = TRUE;

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
	i_free(ssl_io->log_prefix);
	ssl_io->log_prefix = i_strdup(prefix);
}

static bool openssl_iostream_is_handshaked(const struct ssl_iostream *ssl_io)
{
	return ssl_io->handshaked;
}

static bool
openssl_iostream_has_handshake_failed(const struct ssl_iostream *ssl_io)
{
	return ssl_io->handshake_failed;
}

static bool
openssl_iostream_has_valid_client_cert(const struct ssl_iostream *ssl_io)
{
	return ssl_io->cert_received && !ssl_io->cert_broken;
}

static bool
openssl_iostream_has_broken_client_cert(struct ssl_iostream *ssl_io)
{
	return ssl_io->cert_received && ssl_io->cert_broken;
}

static const char *
openssl_iostream_get_peer_name(struct ssl_iostream *ssl_io)
{
	X509 *x509;
	char *name;
	int len;

	if (!ssl_iostream_has_valid_client_cert(ssl_io))
		return NULL;

	x509 = SSL_get_peer_certificate(ssl_io->ssl);
	i_assert(x509 != NULL);

	len = X509_NAME_get_text_by_NID(X509_get_subject_name(x509),
					ssl_io->username_nid, NULL, 0);
	if (len < 0)
		name = "";
	else {
		name = t_malloc0(len + 1);
		if (X509_NAME_get_text_by_NID(X509_get_subject_name(x509),
					      ssl_io->username_nid,
					      name, len + 1) < 0)
			name = "";
		else if (strlen(name) != (size_t)len) {
			/* NUL characters in name. Someone's trying to fake
			   being another user? Don't allow it. */
			name = "";
		}
	}
	X509_free(x509);
	
	return *name == '\0' ? NULL : name;
}

static const char *openssl_iostream_get_server_name(struct ssl_iostream *ssl_io)
{
	return ssl_io->sni_host;
}

static const char *
openssl_iostream_get_compression(struct ssl_iostream *ssl_io)
{
#if defined(HAVE_SSL_COMPRESSION) && !defined(OPENSSL_NO_COMP)
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
#if defined(HAVE_SSL_COMPRESSION) && !defined(OPENSSL_NO_COMP)
	const COMP_METHOD *comp;
#endif
	const char *comp_str;
	int bits, alg_bits;

	if (!ssl_io->handshaked)
		return "";

	cipher = SSL_get_current_cipher(ssl_io->ssl);
	bits = SSL_CIPHER_get_bits(cipher, &alg_bits);
#if defined(HAVE_SSL_COMPRESSION) && !defined(OPENSSL_NO_COMP)
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
#if defined(HAVE_SSL_CIPHER_get_kx_nid)
	int nid = SSL_CIPHER_get_kx_nid(cipher);
	return OBJ_nid2sn(nid);
#else
	char buf[128];
	const char *desc, *ptr;
	if ((desc = SSL_CIPHER_description(cipher, buf, sizeof(buf)))==NULL ||
	    (ptr = strstr(desc, "Kx=")) == NULL)
		return "";
	return t_strcut(ptr+3, ' ');
#endif
}

static const char *
openssl_iostream_get_protocol_name(struct ssl_iostream *ssl_io)
{
	if (!ssl_io->handshaked)
		return NULL;
	return SSL_get_version(ssl_io->ssl);
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
	.is_handshaked = openssl_iostream_is_handshaked,
	.has_handshake_failed = openssl_iostream_has_handshake_failed,
	.has_valid_client_cert = openssl_iostream_has_valid_client_cert,
	.has_broken_client_cert = openssl_iostream_has_broken_client_cert,
	.cert_match_name = openssl_iostream_cert_match_name,
	.get_peer_name = openssl_iostream_get_peer_name,
	.get_server_name = openssl_iostream_get_server_name,
	.get_compression = openssl_iostream_get_compression,
	.get_security_string = openssl_iostream_get_security_string,
	.get_last_error = openssl_iostream_get_last_error,
	.get_cipher = openssl_iostream_get_cipher,
	.get_pfs = openssl_iostream_get_pfs,
	.get_protocol_name = openssl_iostream_get_protocol_name,
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



static const char hexcodes[] = "0123456789ABCDEF";

const char *ssl_iostream_get_fingerprint(struct iostream *ssl_io)
{
    return __ssl_iostream_get_fingerprint(iostream, 0);
}

const char *ssl_iostream_get_fingerprint_base64(struct iostream *ssl_io)
{
	return __ssl_iostream_get_fingerprint(iostream, 1);
}

const char *__ssl_iostream_get_fingerprint(struct iostream *ssl_io, bool base64mode)
{
    X509 *x509;
    char *peer_fingerprint = NULL;
    const char *ssl_cert_md_algorithm = NULL;
    const EVP_MD *md_alg;
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    int j;

    /* begin base64: needed for base64 handling */
    char *fingerprint_ascii_ptr = NULL;
    char arr[21];
    int index = 0;
    int num = 0;
    /* end base64 */

    if (!ssl_proxy_has_valid_client_cert(proxy))
        return NULL;

    x509 = SSL_get_peer_certificate(proxy->ssl);
    if (x509 == NULL)
        return NULL; /* we should have had it.. */

    ssl_cert_md_algorithm = t_strdup_printf("%s", proxy->ssl_set->ssl_cert_md_algorithm);

    if ((md_alg = EVP_get_digestbyname(ssl_cert_md_algorithm)) == 0) {
        i_panic("Certificate digest algorithm \"%s\" not found ...",
                ssl_cert_md_algorithm);
    }

    /* Fails when serialization to ASN.1 runs out of memory */
    if (X509_digest(x509, md_alg, md_buf, &md_len) == 0) {
        i_fatal("Certificate error computing certificate %s digest (out of memory?)",
                ssl_cert_md_algorithm);
    }

    /* Check for OpenSSL contract violation */
    if (md_len > EVP_MAX_MD_SIZE || md_len >= INT_MAX / 3)
        i_panic("unexpectedly large %s digest size: %u",
                ssl_cert_md_algorithm, md_len);

    peer_fingerprint = i_malloc(md_len * 3);

    for (j = 0; j < (int) md_len; j++) {
        if (!base64mode) {
            peer_fingerprint[j * 3] = hexcodes[(md_buf[j] & 0xf0) >> 4U];
            peer_fingerprint[(j * 3) + 1] = hexcodes[(md_buf[j] & 0x0f)];
            if (j + 1 != (int) md_len) {
                peer_fingerprint[(j * 3) + 2] = ':';
            } else {
                peer_fingerprint[(j * 3) + 2] = '\0';
            }
        } else {
            peer_fingerprint[j * 2] = hexcodes[(md_buf[j] & 0xf0) >> 4U];
            peer_fingerprint[(j * 2) + 1] = hexcodes[(md_buf[j] & 0x0f)];
        }

        if (proxy->ssl_set->ssl_cert_debug) {
            if (!base64mode) {
                i_debug("fingerprint: %s", peer_fingerprint);
            } else {
                i_debug("fingerprint_compressed: %s", peer_fingerprint);
            }
        }
    }

    if (proxy->ssl_set->ssl_cert_info) {
        if (!base64mode) {
            i_info("x509 fingerprint found: %s", peer_fingerprint);
        } else {
            i_info("x509 fingerprint_compressed found: %s", peer_fingerprint);
        }
    }

    if (base64mode) {
        fingerprint_ascii_ptr   = peer_fingerprint;
        /* convert hex to int array */
        while(sscanf(fingerprint_ascii_ptr,"%02x",&num) == 1){
            fingerprint_ascii_ptr += 2;
            arr[index] = num;
            index++;
            if (proxy->ssl_set->ssl_cert_debug) {
                i_debug("fingerprint_binary: %s", arr);
            }
        }
        if (proxy->ssl_set->ssl_cert_debug) {
            i_debug("x509 fingerprint_binary: %s", arr);
        }
        i_free(peer_fingerprint);
        return (const char *)__base64(arr, index);
    }

    /* non base64 case */
    return (const char *)peer_fingerprint;
}

char *__base64(const char *input, int length)
{
    char *buff;

    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    buff = i_malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;

    BIO_free_all(b64);

    return buff;
}
