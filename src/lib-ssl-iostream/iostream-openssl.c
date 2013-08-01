/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "ostream-private.h"
#include "iostream-openssl.h"

#include <openssl/err.h>

static void openssl_iostream_free(struct ssl_iostream *ssl_io);

static void
openssl_iostream_set_error(struct ssl_iostream *ssl_io, const char *str)
{
	i_free(ssl_io->last_error);
	ssl_io->last_error = i_strdup(str);
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
			i_warning("%sSSL alert: where=0x%x, ret=%d: %s %s",
				  ssl_io->log_prefix, where, ret,
				  SSL_alert_type_string_long(ret),
				  SSL_alert_desc_string_long(ret));
			break;
		}
	} else if (ret == 0) {
		i_warning("%sSSL failed: where=0x%x: %s",
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
			ssl_iostream_get_use_certificate_error(cert));
		return -1;
	}
	return 0;
}

static int
openssl_iostream_use_key(struct ssl_iostream *ssl_io,
			 const struct ssl_iostream_settings *set,
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

	subject = X509_get_subject_name(ctx->current_cert);
	if (subject == NULL ||
	    X509_NAME_oneline(subject, certname, sizeof(certname)) == NULL)
		certname[0] = '\0';
	else
		certname[sizeof(certname)-1] = '\0'; /* just in case.. */
	if (!preverify_ok) {
		openssl_iostream_set_error(ssl_io, t_strdup_printf(
			"Received invalid SSL certificate: %s: %s",
			X509_verify_cert_error_string(ctx->error), certname));
		if (ssl_io->verbose_invalid_cert)
			i_info("%s", ssl_io->last_error);
	} else if (ssl_io->verbose) {
		i_info("Received valid SSL certificate: %s", certname);
	}
	if (!preverify_ok) {
		ssl_io->cert_broken = TRUE;
		if (ssl_io->require_valid_cert) {
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
	const struct ssl_iostream_settings *ctx_set = ssl_io->ctx->set;
	int verify_flags;

	if (set->verbose)
		SSL_set_info_callback(ssl_io->ssl, openssl_info_callback);

       if (set->cipher_list != NULL &&
	    strcmp(ctx_set->cipher_list, set->cipher_list) != 0) {
		if (!SSL_set_cipher_list(ssl_io->ssl, set->cipher_list)) {
			*error_r = t_strdup_printf(
				"Can't set cipher list to '%s': %s",
				set->cipher_list, openssl_iostream_error());
			return -1;
		}
	}
	if (set->protocols != NULL) {
		SSL_clear_options(ssl_io->ssl, OPENSSL_ALL_PROTOCOL_OPTIONS);
		SSL_set_options(ssl_io->ssl,
				openssl_get_protocol_options(set->protocols));
	}

	if (set->cert != NULL && strcmp(ctx_set->cert, set->cert) != 0) {
		if (openssl_iostream_use_certificate(ssl_io, set->cert, error_r) < 0)
			return -1;
	}
	if (set->key != NULL && strcmp(ctx_set->key, set->key) != 0) {
		if (openssl_iostream_use_key(ssl_io, set, error_r) < 0)
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
	ssl_io->require_valid_cert = set->require_valid_cert;
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
	ssl_io->ssl = ssl;
	ssl_io->bio_ext = bio_ext;
	ssl_io->plain_input = *input;
	ssl_io->plain_output = *output;
	ssl_io->host = i_strdup(host);
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
	i_stream_unref(&ssl_io->plain_input);
	o_stream_unref(&ssl_io->plain_output);
	BIO_free(ssl_io->bio_ext);
	SSL_free(ssl_io->ssl);
	i_free(ssl_io->last_error);
	i_free(ssl_io->host);
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

static void openssl_iostream_destroy(struct ssl_iostream *ssl_io)
{
	(void)SSL_shutdown(ssl_io->ssl);
	(void)openssl_iostream_more(ssl_io);
	(void)o_stream_flush(ssl_io->plain_output);

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
			i_assert(ssl_io->plain_output->closed ||
				 ssl_io->plain_output->stream_errno != 0);
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
			   const unsigned char **data_r, size_t *size_r)
{
	*data_r = i_stream_get_data(ssl_io->plain_input, size_r);
	if (*size_r > 0)
		return 0;

	if (!ssl_io->input_handler) {
		/* read plain_input only when we came here from input handler.
		   this makes sure that we don't get stuck with some input
		   unexpectedly buffered. */
		return 0;
	}

	if (i_stream_read_data(ssl_io->plain_input, data_r, size_r, 0) < 0)
		return -1;
	return 0;
}

static bool openssl_iostream_bio_input(struct ssl_iostream *ssl_io)
{
	const unsigned char *data;
	size_t bytes, size;
	int ret;
	bool bytes_read = FALSE;

	while ((bytes = BIO_ctrl_get_write_guarantee(ssl_io->bio_ext)) > 0) {
		/* bytes contains how many bytes we can write to bio_ext */
		ssl_io->plain_input->real_stream->try_alloc_limit = bytes;
		ret = openssl_iostream_read_more(ssl_io, &data, &size);
		ssl_io->plain_input->real_stream->try_alloc_limit = 0;
		if (ret == -1 && size == 0 && !bytes_read) {
			ssl_io->plain_stream_errno =
				ssl_io->plain_input->stream_errno;
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
		ssl_io->plain_stream_errno = EINVAL;
		ssl_io->closed = TRUE;
		return FALSE;
	}
	if (i_stream_get_data_size(ssl_io->plain_input) > 0) {
		i_error("SSL: Too much data in buffered plain input buffer");
		ssl_io->plain_stream_errno = EINVAL;
		ssl_io->closed = TRUE;
		return FALSE;
	}
	if (bytes_read) {
		if (ssl_io->ostream_flush_waiting_input) {
			ssl_io->ostream_flush_waiting_input = FALSE;
			o_stream_set_flush_pending(ssl_io->plain_output, TRUE);
		}
		ssl_io->want_read = FALSE;
	}
	return bytes_read;
}

bool openssl_iostream_bio_sync(struct ssl_iostream *ssl_io)
{
	bool ret;

	ret = openssl_iostream_bio_output(ssl_io);
	if (openssl_iostream_bio_input(ssl_io))
		ret = TRUE;
	return ret;
}

int openssl_iostream_more(struct ssl_iostream *ssl_io)
{
	int ret;

	if (!ssl_io->handshaked) {
		if ((ret = ssl_iostream_handshake(ssl_io)) <= 0)
			return ret;
	}
	(void)openssl_iostream_bio_sync(ssl_io);
	return 1;
}

static int
openssl_iostream_handle_error_full(struct ssl_iostream *ssl_io, int ret,
				   const char *func_name, bool write_error)
{
	const char *errstr = NULL;
	int err;

	err = SSL_get_error(ssl_io->ssl, ret);
	switch (err) {
	case SSL_ERROR_WANT_WRITE:
		if (!openssl_iostream_bio_sync(ssl_io)) {
			if (!write_error)
				i_panic("SSL ostream buffer size not unlimited");
			return 0;
		}
		if (ssl_io->closed) {
			errno = ssl_io->plain_stream_errno != 0 ?
				ssl_io->plain_stream_errno : EPIPE;
			return -1;
		}
		return 1;
	case SSL_ERROR_WANT_READ:
		ssl_io->want_read = TRUE;
		(void)openssl_iostream_bio_sync(ssl_io);
		if (ssl_io->closed) {
			errno = ssl_io->plain_stream_errno != 0 ?
				ssl_io->plain_stream_errno : EPIPE;
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
			errno = ECONNRESET;
			errstr = "Disconnected";
			break;
		}
		errstr = t_strdup_printf("%s syscall failed: %s",
					 func_name, errstr);
		break;
	case SSL_ERROR_ZERO_RETURN:
		/* clean connection closing */
		errno = ECONNRESET;
		break;
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

	if (errstr != NULL)
		openssl_iostream_set_error(ssl_io, errstr);
	return -1;
}

int openssl_iostream_handle_error(struct ssl_iostream *ssl_io, int ret,
				  const char *func_name)
{
	return openssl_iostream_handle_error_full(ssl_io, ret, func_name, FALSE);
}

int openssl_iostream_handle_write_error(struct ssl_iostream *ssl_io, int ret,
					const char *func_name)
{
	return openssl_iostream_handle_error_full(ssl_io, ret, func_name, TRUE);
}

static int
openssl_iostream_cert_match_name(struct ssl_iostream *ssl_io,
				 const char *verify_name)
{
	if (!ssl_iostream_has_valid_client_cert(ssl_io))
		return -1;

	return openssl_cert_match_name(ssl_io->ssl, verify_name);
}

static int openssl_iostream_handshake(struct ssl_iostream *ssl_io)
{
	const char *error = NULL;
	int ret;

	i_assert(!ssl_io->handshaked);

	if (ssl_io->ctx->client_ctx) {
		while ((ret = SSL_connect(ssl_io->ssl)) <= 0) {
			ret = openssl_iostream_handle_error(ssl_io, ret,
							    "SSL_connect()");
			if (ret <= 0)
				return ret;
		}
	} else {
		while ((ret = SSL_accept(ssl_io->ssl)) <= 0) {
			ret = openssl_iostream_handle_error(ssl_io, ret,
							    "SSL_accept()");
			if (ret <= 0)
				return ret;
		}
	}
	/* handshake finished */
	(void)openssl_iostream_bio_sync(ssl_io);

	if (ssl_io->handshake_callback != NULL) {
		if (ssl_io->handshake_callback(&error, ssl_io->handshake_context) < 0) {
			i_assert(error != NULL);
			i_stream_close(ssl_io->plain_input);
			o_stream_close(ssl_io->plain_output);
			openssl_iostream_set_error(ssl_io, error);
			ssl_io->handshake_failed = TRUE;
			errno = EINVAL;
			return -1;
		}
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
		name = t_malloc(len + 1);
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
	return ssl_io->host;
}

static const char *
openssl_iostream_get_security_string(struct ssl_iostream *ssl_io)
{
	const SSL_CIPHER *cipher;
#ifdef HAVE_SSL_COMPRESSION
	const COMP_METHOD *comp;
#endif
	const char *comp_str;
	int bits, alg_bits;

	if (!ssl_io->handshaked)
		return "";

	cipher = SSL_get_current_cipher(ssl_io->ssl);
	bits = SSL_CIPHER_get_bits(cipher, &alg_bits);
#ifdef HAVE_SSL_COMPRESSION
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

const struct iostream_ssl_vfuncs ssl_vfuncs = {
	openssl_iostream_context_init_client,
	openssl_iostream_context_init_server,
	openssl_iostream_context_deinit,

	openssl_iostream_generate_params,
	openssl_iostream_context_import_params,

	openssl_iostream_create,
	openssl_iostream_unref,
	openssl_iostream_destroy,

	openssl_iostream_handshake,
	openssl_iostream_set_handshake_callback,

	openssl_iostream_set_log_prefix,
	openssl_iostream_is_handshaked,
	openssl_iostream_has_handshake_failed,
	openssl_iostream_has_valid_client_cert,
	openssl_iostream_has_broken_client_cert,
	openssl_iostream_cert_match_name,
	openssl_iostream_get_peer_name,
	openssl_iostream_get_server_name,
	openssl_iostream_get_security_string,
	openssl_iostream_get_last_error
};
