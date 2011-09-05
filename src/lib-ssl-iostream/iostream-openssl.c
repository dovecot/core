/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-openssl.h"

#include <openssl/err.h>

static void ssl_iostream_free(struct ssl_iostream *ssl_io);

static void ssl_info_callback(const SSL *ssl, int where, int ret)
{
	struct ssl_iostream *ssl_io;

	ssl_io = SSL_get_ex_data(ssl, dovecot_ssl_extdata_index);
	if ((where & SSL_CB_ALERT) != 0) {
		i_warning("%s: SSL alert: where=0x%x, ret=%d: %s %s",
			  ssl_io->source, where, ret,
			  SSL_alert_type_string_long(ret),
			  SSL_alert_desc_string_long(ret));
	} else if (ret == 0) {
		i_warning("%s: SSL failed: where=0x%x: %s",
			  ssl_io->source, where, SSL_state_string_long(ssl));
	} else {
		i_warning("%s: SSL: where=0x%x, ret=%d: %s",
			  ssl_io->source, where, ret,
			  SSL_state_string_long(ssl));
	}
}

static int
ssl_iostream_use_certificate(struct ssl_iostream *ssl_io, const char *cert)
{
	BIO *in;
	X509 *x;
	int ret = 0;

	in = BIO_new_mem_buf(t_strdup_noconst(cert), strlen(cert));
	if (in == NULL) {
		i_error("BIO_new_mem_buf() failed: %s", ssl_iostream_error());
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
		i_error("%s: Can't load ssl_cert: %s", ssl_io->source,
			ssl_iostream_get_use_certificate_error(cert));
		return -1;
	}
	return 0;
}

static int
ssl_iostream_use_key(struct ssl_iostream *ssl_io,
		     const struct ssl_iostream_settings *set)
{
	EVP_PKEY *pkey;
	int ret = 0;

	if (ssl_iostream_load_key(set, ssl_io->source, &pkey) < 0)
		return -1;
	if (SSL_use_PrivateKey(ssl_io->ssl, pkey) != 1) {
		i_error("%s: Can't load SSL private key: %s",
			ssl_io->source, ssl_iostream_key_load_error());
		ret = -1;
	}
	EVP_PKEY_free(pkey);
	return ret;
}

static int
ssl_iostream_verify_client_cert(int preverify_ok, X509_STORE_CTX *ctx)
{
	int ssl_extidx = SSL_get_ex_data_X509_STORE_CTX_idx();
	SSL *ssl;
	struct ssl_iostream *ssl_io;

	ssl = X509_STORE_CTX_get_ex_data(ctx, ssl_extidx);
	ssl_io = SSL_get_ex_data(ssl, dovecot_ssl_extdata_index);
	ssl_io->cert_received = TRUE;

	if (ssl_io->verbose ||
	    (ssl_io->verbose_invalid_cert && !preverify_ok)) {
		char buf[1024];
		X509_NAME *subject;

		subject = X509_get_subject_name(ctx->current_cert);
		if (X509_NAME_oneline(subject, buf, sizeof(buf)) == NULL)
			buf[0] = '\0';
		else
			buf[sizeof(buf)-1] = '\0'; /* just in case.. */
		if (!preverify_ok) {
			i_info("Invalid certificate: %s: %s",
			       X509_verify_cert_error_string(ctx->error), buf);
		} else {
			i_info("Valid certificate: %s", buf);
		}
	}
	if (!preverify_ok) {
		ssl_io->cert_broken = TRUE;
		if (ssl_io->require_valid_cert)
			return 0;
	}
	return 1;
}

static int
ssl_iostream_set(struct ssl_iostream *ssl_io,
		 const struct ssl_iostream_settings *set)
{
	const struct ssl_iostream_settings *ctx_set = ssl_io->ctx->set;

	if (set->verbose)
		SSL_set_info_callback(ssl_io->ssl, ssl_info_callback);

	if (set->cipher_list != NULL &&
	    strcmp(ctx_set->cipher_list, set->cipher_list) != 0) {
		if (!SSL_set_cipher_list(ssl_io->ssl, set->cipher_list)) {
			i_error("%s: Can't set cipher list to '%s': %s",
				ssl_io->source, set->cipher_list,
				ssl_iostream_error());
		}
		return -1;

	}
	if (set->cert != NULL && strcmp(ctx_set->cert, set->cert) != 0) {
		if (ssl_iostream_use_certificate(ssl_io, set->cert) < 0)
			return -1;
	}
	if (set->key != NULL && strcmp(ctx_set->key, set->key) != 0) {
		if (ssl_iostream_use_key(ssl_io, set) < 0)
			return -1;
	}
	if (set->verify_remote_cert) {
		SSL_set_verify(ssl_io->ssl,
			       SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
			       ssl_iostream_verify_client_cert);
	}

	if (set->cert_username_field != NULL) {
		ssl_io->username_nid = OBJ_txt2nid(set->cert_username_field);
		if (ssl_io->username_nid == NID_undef) {
			i_error("%s: Invalid cert_username_field: %s",
				ssl_io->source, set->cert_username_field);
		}
	} else {
		ssl_io->username_nid = ssl_io->ctx->username_nid;
	}

	ssl_io->verbose = set->verbose;
	ssl_io->verbose_invalid_cert = set->verbose_invalid_cert;
	ssl_io->require_valid_cert = set->require_valid_cert;
	return 0;
}

int io_stream_create_ssl(struct ssl_iostream_context *ctx, const char *source,
			 const struct ssl_iostream_settings *set,
			 struct istream **input, struct ostream **output,
			 struct ssl_iostream **iostream_r)
{
	struct ssl_iostream *ssl_io;
	SSL *ssl;
	BIO *bio_int, *bio_ext;
	int ret;

	ssl = SSL_new(ctx->ssl_ctx);
	if (ssl == NULL) {
		i_error("SSL_new() failed: %s", ssl_iostream_error());
		return -1;
	}

	if (BIO_new_bio_pair(&bio_int, 0, &bio_ext, 0) != 1) {
		i_error("BIO_new_bio_pair() failed: %s", ssl_iostream_error());
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
	ssl_io->source = i_strdup(source);
	SSL_set_bio(ssl_io->ssl, bio_int, bio_int);
        SSL_set_ex_data(ssl_io->ssl, dovecot_ssl_extdata_index, ssl_io);

	i_stream_ref(ssl_io->plain_input);
	o_stream_ref(ssl_io->plain_output);

	T_BEGIN {
		ret = ssl_iostream_set(ssl_io, set);
	} T_END;
	if (ret < 0) {
		ssl_iostream_free(ssl_io);
		return -1;
	}

	o_stream_uncork(ssl_io->plain_output);

	*input = i_stream_create_ssl(ssl_io);
	*output = o_stream_create_ssl(ssl_io);

	ssl_io->ssl_output = *output;
	*iostream_r = ssl_io;
	return 0;
}

static void ssl_iostream_free(struct ssl_iostream *ssl_io)
{
	i_stream_unref(&ssl_io->plain_input);
	o_stream_unref(&ssl_io->plain_output);
	BIO_free(ssl_io->bio_ext);
	SSL_free(ssl_io->ssl);
	i_free(ssl_io->last_error);
	i_free(ssl_io->source);
	i_free(ssl_io);
}

void ssl_iostream_unref(struct ssl_iostream **_ssl_io)
{
	struct ssl_iostream *ssl_io = *_ssl_io;

	*_ssl_io = NULL;

	i_assert(ssl_io->refcount > 0);
	if (--ssl_io->refcount >= 0)
		return;

	ssl_iostream_free(ssl_io);
}

static bool ssl_iostream_bio_output(struct ssl_iostream *ssl_io)
{
	size_t bytes, max_bytes;
	ssize_t sent;
	unsigned char buffer[1024];
	bool bytes_sent = FALSE;
	int ret;

	while ((bytes = BIO_ctrl_pending(ssl_io->bio_ext)) > 0) {
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

		ret = BIO_read(ssl_io->bio_ext, buffer, bytes);
		i_assert(ret == (int)bytes);

		sent = o_stream_send(ssl_io->plain_output, buffer, bytes);
		if (sent < 0) {
			i_assert(ssl_io->plain_output->stream_errno != 0);
			ssl_io->ssl_output->stream_errno =
				ssl_io->plain_output->stream_errno;
			break;
		}
		i_assert(sent == (ssize_t)bytes);
		bytes_sent = TRUE;
	}
	return bytes_sent;
}

static bool ssl_iostream_bio_input(struct ssl_iostream *ssl_io)
{
	const unsigned char *data;
	size_t size;
	bool bytes_read = FALSE;
	int ret;

	while (BIO_ctrl_get_read_request(ssl_io->bio_ext) > 0) {
		(void)i_stream_read_data(ssl_io->plain_input, &data, &size, 0);
		if (size == 0) {
			/* wait for more input */
			break;
		}
		ret = BIO_write(ssl_io->bio_ext, data, size);
		i_assert(ret == (ssize_t)size);

		i_stream_skip(ssl_io->plain_input, size);
		bytes_read = TRUE;
	}
	return bytes_read;
}

bool ssl_iostream_bio_sync(struct ssl_iostream *ssl_io)
{
	bool ret;

	ret = ssl_iostream_bio_output(ssl_io);
	if (ssl_iostream_bio_input(ssl_io))
		ret = TRUE;
	return ret;
}

int ssl_iostream_handle_error(struct ssl_iostream *ssl_io, int ret,
			      const char *func_name)
{
	const char *errstr = NULL;
	int err;

	err = SSL_get_error(ssl_io->ssl, ret);
	switch (err) {
	case SSL_ERROR_WANT_WRITE:
		if (!ssl_iostream_bio_sync(ssl_io))
			return 0;
		return 1;
	case SSL_ERROR_WANT_READ:
		if (!ssl_iostream_bio_sync(ssl_io))
			return 0;
		return 1;
	case SSL_ERROR_SYSCALL:
		/* eat up the error queue */
		if (ERR_peek_error() != 0) {
			errstr = ssl_iostream_error();
			errno = EINVAL;
		} else if (ret != 0) {
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
					 func_name, ssl_iostream_error());
		errno = EINVAL;
		break;
	default:
		errstr = t_strdup_printf("%s failed: unknown failure %d (%s)",
					 func_name, err, ssl_iostream_error());
		errno = EINVAL;
		break;
	}

	if (errstr != NULL) {
		i_free(ssl_io->last_error);
		ssl_io->last_error = i_strdup(errstr);
	}
	return -1;
}

int ssl_iostream_handshake(struct ssl_iostream *ssl_io)
{
	int ret;

	i_assert(!ssl_io->handshaked);

	if (ssl_io->ctx->client_ctx) {
		while ((ret = SSL_connect(ssl_io->ssl)) <= 0) {
			ret = ssl_iostream_handle_error(ssl_io, ret,
							"SSL_connect()");
			if (ret <= 0)
				return ret;
		}
	} else {
		while ((ret = SSL_accept(ssl_io->ssl)) <= 0) {
			ret = ssl_iostream_handle_error(ssl_io, ret,
							"SSL_accept()");
			if (ret <= 0)
				return ret;
		}
	}
	(void)ssl_iostream_bio_sync(ssl_io);

	i_free_and_null(ssl_io->last_error);
	ssl_io->handshaked = TRUE;

	if (ssl_io->handshake_callback != NULL) {
		if (ssl_io->handshake_callback(ssl_io->handshake_context) < 0) {
			errno = EINVAL;
			return -1;
		}
	}
	if (ssl_io->ssl_output != NULL)
		(void)o_stream_flush(ssl_io->ssl_output);
	return 1;
}

void ssl_iostream_set_handshake_callback(struct ssl_iostream *ssl_io,
					 int (*callback)(void *context),
					 void *context)
{
	ssl_io->handshake_callback = callback;
	ssl_io->handshake_context = context;
}

bool ssl_iostream_is_handshaked(const struct ssl_iostream *ssl_io)
{
	return ssl_io->handshaked;
}

bool ssl_iostream_has_valid_client_cert(const struct ssl_iostream *ssl_io)
{
	return ssl_io->cert_received && !ssl_io->cert_broken;
}

bool ssl_iostream_has_broken_client_cert(struct ssl_iostream *ssl_io)
{
	return ssl_io->cert_received && ssl_io->cert_broken;
}

const char *ssl_iostream_get_peer_name(struct ssl_iostream *ssl_io)
{
	X509 *x509;
	char *name;
	int len;

	if (!ssl_iostream_has_valid_client_cert(ssl_io))
		return NULL;

	x509 = SSL_get_peer_certificate(ssl_io->ssl);
	if (x509 == NULL)
		return NULL; /* we should have had it.. */

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

const char *ssl_iostream_get_security_string(struct ssl_iostream *ssl_io)
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

const char *ssl_iostream_get_last_error(struct ssl_iostream *ssl_io)
{
	return ssl_io->last_error;
}
