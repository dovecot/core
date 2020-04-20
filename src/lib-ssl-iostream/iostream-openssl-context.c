/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "safe-memset.h"
#include "iostream-openssl.h"
#include "dovecot-openssl-common.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#if !defined(OPENSSL_NO_ECDH) && OPENSSL_VERSION_NUMBER >= 0x10000000L
#  define HAVE_ECDH
#endif

struct ssl_iostream_password_context {
	const char *password;
	const char *error;
};

static bool ssl_global_initialized = FALSE;
int dovecot_ssl_extdata_index;

static RSA *ssl_gen_rsa_key(SSL *ssl ATTR_UNUSED,
			    int is_export ATTR_UNUSED, int keylength)
{
#ifdef HAVE_RSA_GENERATE_KEY_EX
	BIGNUM *bn = BN_new();
	RSA *rsa = RSA_new();

	if (bn != NULL && BN_set_word(bn, RSA_F4) != 0 &&
	    RSA_generate_key_ex(rsa, keylength, bn, NULL) != 0) {
		BN_free(bn);
		return rsa;
	}

	if (bn != NULL)
		BN_free(bn);
	if (rsa != NULL)
		RSA_free(rsa);
	return NULL;
#else
	return RSA_generate_key(keylength, RSA_F4, NULL, NULL);
#endif
}

static DH *ssl_tmp_dh_callback(SSL *ssl ATTR_UNUSED,
			       int is_export ATTR_UNUSED, int keylength ATTR_UNUSED)
{
	i_error("Diffie-Hellman key exchange requested, "
		"but no DH parameters provided. Set ssl_dh=</path/to/dh.pem");
	return NULL;
}

static int
pem_password_callback(char *buf, int size, int rwflag ATTR_UNUSED,
		      void *userdata)
{
	struct ssl_iostream_password_context *ctx = userdata;

	if (ctx->password == NULL) {
		ctx->error = "SSL private key file is password protected, "
			"but password isn't given";
		return 0;
	}

	if (i_strocpy(buf, ctx->password, size) < 0) {
		ctx->error = "SSL private key password is too long";
		return 0;
	}
	return strlen(buf);
}

int openssl_iostream_load_key(const struct ssl_iostream_cert *set,
			      const char *set_name,
			      EVP_PKEY **pkey_r, const char **error_r)
{
	struct ssl_iostream_password_context ctx;
	EVP_PKEY *pkey;
	BIO *bio;
	char *key;

	key = t_strdup_noconst(set->key);
	bio = BIO_new_mem_buf(key, strlen(key));
	if (bio == NULL) {
		*error_r = t_strdup_printf("BIO_new_mem_buf() failed: %s",
					   openssl_iostream_error());
		safe_memset(key, 0, strlen(key));
		return -1;
	}

	ctx.password = set->key_password;
	ctx.error = NULL;

	pkey = PEM_read_bio_PrivateKey(bio, NULL, pem_password_callback, &ctx);
	if (pkey == NULL && ctx.error == NULL) {
		ctx.error = t_strdup_printf(
			"Couldn't parse private SSL key (%s setting): %s",
			set_name, openssl_iostream_error());
	}
	BIO_free(bio);

	safe_memset(key, 0, strlen(key));
	*pkey_r = pkey;
	*error_r = ctx.error;
	return pkey == NULL ? -1 : 0;
}

static
int openssl_iostream_load_dh(const struct ssl_iostream_settings *set,
			     DH **dh_r, const char **error_r)
{
	DH *dh;
	BIO *bio;
	char *dhvalue;

	dhvalue = t_strdup_noconst(set->dh);
	bio = BIO_new_mem_buf(dhvalue, strlen(dhvalue));

	if (bio == NULL) {
		*error_r = t_strdup_printf("BIO_new_mem_buf() failed: %s",
					   openssl_iostream_error());
		return -1;
	}

	dh = NULL;
	dh = PEM_read_bio_DHparams(bio, &dh, NULL, NULL);

	if (dh == NULL) {
		*error_r = t_strdup_printf("Couldn't parse DH parameters: %s",
					   openssl_iostream_error());
	}
	BIO_free(bio);
	*dh_r = dh;
	return dh == NULL ? -1 : 0;
}

static int
ssl_iostream_ctx_use_key(struct ssl_iostream_context *ctx, const char *set_name,
			 const struct ssl_iostream_cert *set,
			 const char **error_r)
{
	EVP_PKEY *pkey;
	int ret = 0;

	if (openssl_iostream_load_key(set, set_name, &pkey, error_r) < 0)
		return -1;
	if (SSL_CTX_use_PrivateKey(ctx->ssl_ctx, pkey) == 0) {
		*error_r = t_strdup_printf(
			"Can't load SSL private key (%s setting): %s",
			set_name, openssl_iostream_key_load_error());
		ret = -1;
	}
	EVP_PKEY_free(pkey);
	return ret;
}

static int
ssl_iostream_ctx_use_dh(struct ssl_iostream_context *ctx,
			const struct ssl_iostream_settings *set,
			const char **error_r)
{
	DH *dh;
	int ret = 0;
	if (*set->dh == '\0') {
		return 0;
	}
	if (openssl_iostream_load_dh(set, &dh, error_r) < 0)
		return -1;
	if (SSL_CTX_set_tmp_dh(ctx->ssl_ctx, dh) == 0) {
		 *error_r = t_strdup_printf(
			"Can't load DH parameters (ssl_dh setting): %s",
			openssl_iostream_key_load_error());
		ret = -1;
	}
	DH_free(dh);
	return ret;
}

static int ssl_ctx_use_certificate_chain(SSL_CTX *ctx, const char *cert)
{
	/* mostly just copy&pasted from SSL_CTX_use_certificate_chain_file() */
	BIO *in;
	X509 *x;
	int ret = 0;

	in = BIO_new_mem_buf(t_strdup_noconst(cert), strlen(cert));
	if (in == NULL)
		i_fatal("BIO_new_mem_buf() failed");

	x = PEM_read_bio_X509(in, NULL, NULL, NULL);
	if (x == NULL)
		goto end;

	ret = SSL_CTX_use_certificate(ctx, x);
	if (ERR_peek_error() != 0)
		ret = 0;

	if (ret != 0) {
#ifdef HAVE_SSL_CTX_SET_CURRENT_CERT
		SSL_CTX_select_current_cert(ctx, x);
#endif
		/* If we could set up our certificate, now proceed to
		 * the CA certificates.
		 */
		X509 *ca;
		int r;
		unsigned long err;
		
		while ((ca = PEM_read_bio_X509(in,NULL,NULL,NULL)) != NULL) {
#ifdef HAVE_SSL_CTX_ADD0_CHAIN_CERT
			r = SSL_CTX_add0_chain_cert(ctx, ca);
#else
			r = SSL_CTX_add_extra_chain_cert(ctx, ca);
#endif
			if (r == 0) {
				X509_free(ca);
				ret = 0;
				goto end;
			}
		}
		/* When the while loop ends, it's usually just EOF. */
		err = ERR_peek_last_error();
		if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
			ERR_clear_error();
		else 
			ret = 0; /* some real error */
		}

end:
	if (x != NULL) X509_free(x);
	BIO_free(in);
#ifdef HAVE_SSL_CTX_SET_CURRENT_CERT
	SSL_CTX_set_current_cert(ctx, SSL_CERT_SET_FIRST);
#endif
	return ret;
}

static int load_ca(X509_STORE *store, const char *ca,
		   STACK_OF(X509_NAME) **xnames_r)
{
	/* mostly just copy&pasted from X509_load_cert_crl_file() */
	STACK_OF(X509_INFO) *inf;
	STACK_OF(X509_NAME) *xnames;
	X509_INFO *itmp;
	X509_NAME *xname;
	BIO *bio;
	int i;

	bio = BIO_new_mem_buf(t_strdup_noconst(ca), strlen(ca));
	if (bio == NULL)
		i_fatal("BIO_new_mem_buf() failed");
	inf = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if (inf == NULL)
		return -1;

	xnames = sk_X509_NAME_new_null();
	if (xnames == NULL)
		i_fatal("sk_X509_NAME_new_null() failed");
	for(i = 0; i < sk_X509_INFO_num(inf); i++) {
		itmp = sk_X509_INFO_value(inf, i);
		if(itmp->x509 != NULL) {
			X509_STORE_add_cert(store, itmp->x509);
			xname = X509_get_subject_name(itmp->x509);
			if (xname != NULL)
				xname = X509_NAME_dup(xname);
			if (xname != NULL)
				sk_X509_NAME_push(xnames, xname);
		}
		if(itmp->crl != NULL)
			X509_STORE_add_crl(store, itmp->crl);
	}
	sk_X509_INFO_pop_free(inf, X509_INFO_free);
	*xnames_r = xnames;
	return 0;
}

static int
load_ca_locations(struct ssl_iostream_context *ctx, const char *ca_file,
		  const char *ca_dir, const char **error_r)
{
	if (SSL_CTX_load_verify_locations(ctx->ssl_ctx, ca_file, ca_dir) != 0)
		return 0;

	if (ca_dir == NULL) {
		*error_r = t_strdup_printf(
			"Can't load CA certs from %s "
			"(ssl_client_ca_file setting): %s",
			ca_file, openssl_iostream_error());
	} else if (ca_file == NULL) {
		*error_r = t_strdup_printf(
			"Can't load CA certs from directory %s "
			"(ssl_client_ca_dir setting): %s",
			ca_dir, openssl_iostream_error());
	} else {
		*error_r = t_strdup_printf(
			"Can't load CA certs from file %s and directory %s "
			"(ssl_client_ca_* settings): %s",
			ca_file, ca_dir, openssl_iostream_error());
	}
	return -1;
}

static void
ssl_iostream_ctx_verify_remote_cert(struct ssl_iostream_context *ctx,
				    STACK_OF(X509_NAME) *ca_names)
{
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
	if (!ctx->set.skip_crl_check) {
		X509_STORE *store;

		store = SSL_CTX_get_cert_store(ctx->ssl_ctx);
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
				     X509_V_FLAG_CRL_CHECK_ALL);
	}
#endif

	SSL_CTX_set_client_CA_list(ctx->ssl_ctx, ca_names);
}

#ifdef HAVE_SSL_GET_SERVERNAME
static int ssl_servername_callback(SSL *ssl, int *al ATTR_UNUSED,
				   void *context ATTR_UNUSED)
{
	struct ssl_iostream *ssl_io;
	const char *host, *error;

	ssl_io = SSL_get_ex_data(ssl, dovecot_ssl_extdata_index);
	host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (SSL_get_servername_type(ssl) != -1) {
		i_free(ssl_io->sni_host);
		ssl_io->sni_host = i_strdup(host);
	} else if (ssl_io->verbose) {
		i_debug("SSL_get_servername() failed");
	}

	if (ssl_io->sni_callback != NULL) {
		if (ssl_io->sni_callback(ssl_io->sni_host, &error,
					 ssl_io->sni_context) < 0) {
			openssl_iostream_set_error(ssl_io, error);
			return SSL_TLSEXT_ERR_ALERT_FATAL;
		}
	}
	return SSL_TLSEXT_ERR_OK;
}
#endif

static int
ssl_iostream_context_load_ca(struct ssl_iostream_context *ctx,
			     const struct ssl_iostream_settings *set,
			     const char **error_r)
{
	X509_STORE *store;
	STACK_OF(X509_NAME) *xnames = NULL;
	const char *ca_file, *ca_dir;
	bool have_ca = FALSE;

	if (set->ca != NULL) {
		store = SSL_CTX_get_cert_store(ctx->ssl_ctx);
		if (load_ca(store, set->ca, &xnames) < 0) {
			*error_r = t_strdup_printf("Couldn't parse ssl_ca: %s",
						   openssl_iostream_error());
			return -1;
		}
		ssl_iostream_ctx_verify_remote_cert(ctx, xnames);
		have_ca = TRUE;
	}
	ca_file = set->ca_file == NULL || *set->ca_file == '\0' ?
		NULL : set->ca_file;
	ca_dir = set->ca_dir == NULL || *set->ca_dir == '\0' ?
		NULL : set->ca_dir;
	if (ca_file != NULL || ca_dir != NULL) {
		if (load_ca_locations(ctx, ca_file, ca_dir, error_r) < 0)
			return -1;
		have_ca = TRUE;
	}
	if (!have_ca && ctx->client_ctx) {
		if (SSL_CTX_set_default_verify_paths(ctx->ssl_ctx) != 1) {
			*error_r = t_strdup_printf(
				"Can't load default CA locations: %s (ssl_client_ca_* settings missing)",
				openssl_iostream_error());
			return -1;
		}
	} else if (!have_ca) {
		*error_r = "Can't verify remote client certs without CA (ssl_ca setting)";
		return -1;
	}
	return 0;
}

static int
ssl_iostream_context_set(struct ssl_iostream_context *ctx,
			 const struct ssl_iostream_settings *set,
			 const char **error_r)
{
	ssl_iostream_settings_init_from(ctx->pool, &ctx->set, set);
	if (set->cipher_list != NULL &&
	    SSL_CTX_set_cipher_list(ctx->ssl_ctx, set->cipher_list) == 0) {
		*error_r = t_strdup_printf(
			"Can't set cipher list to '%s' (ssl_cipher_list setting): %s",
			set->cipher_list, openssl_iostream_error());
		return -1;
	}
#ifdef HAVE_SSL_CTX_SET1_CURVES_LIST
	if (set->curve_list != NULL && strlen(set->curve_list) > 0 &&
		SSL_CTX_set1_curves_list(ctx->ssl_ctx, set->curve_list) == 0) {
		*error_r = t_strdup_printf(
			"Can't set curve list to '%s' (ssl_curve_list setting)",
			set->curve_list);
		return -1;
	}
#endif
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
	if (set->ciphersuites != NULL &&
	    SSL_CTX_set_ciphersuites(ctx->ssl_ctx, set->ciphersuites) == 0) {
		*error_r = t_strdup_printf("Can't set ciphersuites to '%s': %s",
			set->cipher_list, openssl_iostream_error());
		return -1;
	}
#endif
	if (set->prefer_server_ciphers) {
		SSL_CTX_set_options(ctx->ssl_ctx,
				    SSL_OP_CIPHER_SERVER_PREFERENCE);
	}
	if (ctx->set.min_protocol != NULL) {
		long opts;
		int min_protocol;
		if (openssl_min_protocol_to_options(ctx->set.min_protocol,
						    &opts, &min_protocol) < 0) {
			*error_r = t_strdup_printf(
					"Unknown ssl_min_protocol setting '%s'",
					set->min_protocol);
			return -1;
		}
#ifdef HAVE_SSL_CTX_SET_MIN_PROTO_VERSION
		SSL_CTX_set_min_proto_version(ctx->ssl_ctx, min_protocol);
#else
		SSL_CTX_set_options(ctx->ssl_ctx, opts);
#endif
	}

	if (set->cert.cert != NULL &&
	    ssl_ctx_use_certificate_chain(ctx->ssl_ctx, set->cert.cert) == 0) {
		*error_r = t_strdup_printf(
			"Can't load SSL certificate (ssl_cert setting): %s",
			openssl_iostream_use_certificate_error(set->cert.cert, NULL));
		return -1;
	}
	if (set->cert.key != NULL) {
		if (ssl_iostream_ctx_use_key(ctx, "ssl_key", &set->cert, error_r) < 0)
			return -1;
	}
	if (set->alt_cert.cert != NULL &&
	    ssl_ctx_use_certificate_chain(ctx->ssl_ctx, set->alt_cert.cert) == 0) {
		*error_r = t_strdup_printf(
			"Can't load alternative SSL certificate "
			"(ssl_alt_cert setting): %s",
			openssl_iostream_use_certificate_error(set->alt_cert.cert, NULL));
		return -1;
	}
	if (set->alt_cert.key != NULL) {
		if (ssl_iostream_ctx_use_key(ctx, "ssl_alt_key", &set->alt_cert, error_r) < 0)
			return -1;
	}

	if (set->dh != NULL) {
		if (ssl_iostream_ctx_use_dh(ctx, set, error_r) < 0)
			return -1;
	}

	/* set trusted CA certs */
	if (set->verify_remote_cert) {
		if (ssl_iostream_context_load_ca(ctx, set, error_r) < 0)
			return -1;
	}

	if (set->cert_username_field != NULL) {
		ctx->username_nid = OBJ_txt2nid(set->cert_username_field);
		if (ctx->username_nid == NID_undef) {
			*error_r = t_strdup_printf(
				"Invalid cert_username_field: %s",
				set->cert_username_field);
			return -1;
		}
	}
#ifdef HAVE_SSL_GET_SERVERNAME
	if (!ctx->client_ctx) {
		if (SSL_CTX_set_tlsext_servername_callback(ctx->ssl_ctx,
					ssl_servername_callback) != 1) {
			if (set->verbose)
				i_debug("OpenSSL library doesn't support SNI");
		}
	}
#endif
	return 0;
}

#if defined(HAVE_ECDH) && !defined(SSL_CTX_set_ecdh_auto)
static int
ssl_proxy_ctx_get_pkey_ec_curve_name(const struct ssl_iostream_settings *set,
				     int *nid_r, const char **error_r)
{
	int nid = 0;
	EVP_PKEY *pkey;
	EC_KEY *eckey;
	const EC_GROUP *ecgrp;

	if (set->cert.key != NULL) {
		if (openssl_iostream_load_key(&set->cert, "ssl_key", &pkey, error_r) < 0)
			return -1;

		if ((eckey = EVP_PKEY_get1_EC_KEY(pkey)) != NULL &&
		    (ecgrp = EC_KEY_get0_group(eckey)) != NULL)
			nid = EC_GROUP_get_curve_name(ecgrp);
		else {
			/* clear errors added by the above calls */
			openssl_iostream_clear_errors();
		}
		EVP_PKEY_free(pkey);
	}
	if (nid == 0 && set->alt_cert.key != NULL) {
		if (openssl_iostream_load_key(&set->alt_cert, "ssl_alt_key", &pkey, error_r) < 0)
			return -1;

		if ((eckey = EVP_PKEY_get1_EC_KEY(pkey)) != NULL &&
		    (ecgrp = EC_KEY_get0_group(eckey)) != NULL)
			nid = EC_GROUP_get_curve_name(ecgrp);
		else {
			/* clear errors added by the above calls */
			openssl_iostream_clear_errors();
		}
		EVP_PKEY_free(pkey);
	}

	*nid_r = nid;
	return 0;
}
#endif

static int
ssl_proxy_ctx_set_crypto_params(SSL_CTX *ssl_ctx,
				const struct ssl_iostream_settings *set,
				const char **error_r ATTR_UNUSED)
{
#if defined(HAVE_ECDH) && !defined(SSL_CTX_set_ecdh_auto)
	EC_KEY *ecdh;
	int nid;
	const char *curve_name;
#endif
	if (SSL_CTX_need_tmp_RSA(ssl_ctx) != 0)
		SSL_CTX_set_tmp_rsa_callback(ssl_ctx, ssl_gen_rsa_key);
	if (set->dh == NULL || *set->dh == '\0')
		SSL_CTX_set_tmp_dh_callback(ssl_ctx, ssl_tmp_dh_callback);
#ifdef HAVE_ECDH
	/* In the non-recommended situation where ECDH cipher suites are being
	   used instead of ECDHE, do not reuse the same ECDH key pair for
	   different sessions. This option improves forward secrecy. */
	SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
#ifdef SSL_CTX_set_ecdh_auto
	/* OpenSSL >= 1.0.2 automatically handles ECDH temporary key parameter
	   selection. The return value of this function changes is changed to
	   bool in OpenSSL 1.1 and is int in OpenSSL 1.0.2+ */
	if ((long)(SSL_CTX_set_ecdh_auto(ssl_ctx, 1)) == 0) {
		/* shouldn't happen */
		*error_r = t_strdup_printf("SSL_CTX_set_ecdh_auto() failed: %s",
					   openssl_iostream_error());
		return -1;
	}
#else
	/* For OpenSSL < 1.0.2, ECDH temporary key parameter selection must be
	   performed manually. Attempt to select the same curve as that used
	   in the server's private EC key file. Otherwise fall back to the
	   NIST P-384 (secp384r1) curve to be compliant with RFC 6460 when
	   AES-256 TLS cipher suites are in use. This fall back option does
	   however make Dovecot non-compliant with RFC 6460 which requires
	   curve NIST P-256 (prime256v1) be used when AES-128 TLS cipher
	   suites are in use. At least the non-compliance is in the form of
	   providing too much security rather than too little. */
	if (ssl_proxy_ctx_get_pkey_ec_curve_name(set, &nid, error_r) < 0)
		return -1;
	ecdh = EC_KEY_new_by_curve_name(nid);
	if (ecdh == NULL) {
		/* Fall back option */
		nid = NID_secp384r1;
		ecdh = EC_KEY_new_by_curve_name(nid);
	}
	if ((curve_name = OBJ_nid2sn(nid)) != NULL && set->verbose) {
		i_debug("SSL: elliptic curve %s will be used for ECDH and"
			" ECDHE key exchanges", curve_name);
	}
	if (ecdh != NULL) {
		SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
		EC_KEY_free(ecdh);
	}
#endif
#endif
#ifdef SSL_OP_SINGLE_DH_USE
	/* Improves forward secrecy with DH parameters, especially if the
	   parameters used aren't strong primes. See OpenSSL manual. */
	SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);
#endif
	return 0;
}

static int
ssl_iostream_context_init_common(struct ssl_iostream_context *ctx,
				 const struct ssl_iostream_settings *set,
				 const char **error_r)
{
	unsigned long ssl_ops = SSL_OP_NO_SSLv2 |
		(SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

	ctx->pool = pool_alloconly_create("ssl iostream context", 4096);

	/* enable all SSL workarounds, except empty fragments as it
	   makes SSL more vulnerable against attacks */
#ifdef SSL_OP_NO_COMPRESSION
	if (!set->compression)
		ssl_ops |= SSL_OP_NO_COMPRESSION;
#endif
#ifdef SSL_OP_NO_TICKET
	if (!set->tickets)
		ssl_ops |= SSL_OP_NO_TICKET;
#endif
	SSL_CTX_set_options(ctx->ssl_ctx, ssl_ops);
#ifdef SSL_MODE_RELEASE_BUFFERS
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
#ifdef SSL_MODE_ENABLE_PARTIAL_WRITE
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
#endif
#ifdef SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif
	if (ssl_proxy_ctx_set_crypto_params(ctx->ssl_ctx, set, error_r) < 0)
		return -1;

	return ssl_iostream_context_set(ctx, set, error_r);
}

int openssl_iostream_context_init_client(const struct ssl_iostream_settings *set,
					 struct ssl_iostream_context **ctx_r,
					 const char **error_r)
{
	struct ssl_iostream_context *ctx;
	SSL_CTX *ssl_ctx;

	if ((ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
		*error_r = t_strdup_printf("SSL_CTX_new() failed: %s",
					   openssl_iostream_error());
		return -1;
	}
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

	ctx = i_new(struct ssl_iostream_context, 1);
	ctx->refcount = 1;
	ctx->ssl_ctx = ssl_ctx;
	ctx->client_ctx = TRUE;
	if (ssl_iostream_context_init_common(ctx, set, error_r) < 0) {
		ssl_iostream_context_unref(&ctx);
		return -1;
	}
	*ctx_r = ctx;
	return 0;
}

int openssl_iostream_context_init_server(const struct ssl_iostream_settings *set,
					 struct ssl_iostream_context **ctx_r,
					 const char **error_r)
{
	struct ssl_iostream_context *ctx;
	SSL_CTX *ssl_ctx;

	if ((ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
		*error_r = t_strdup_printf("SSL_CTX_new() failed: %s",
					   openssl_iostream_error());
		return -1;
	}

	ctx = i_new(struct ssl_iostream_context, 1);
	ctx->refcount = 1;
	ctx->ssl_ctx = ssl_ctx;
	if (ssl_iostream_context_init_common(ctx, set, error_r) < 0) {
		ssl_iostream_context_unref(&ctx);
		return -1;
	}
	*ctx_r = ctx;
	return 0;
}

void openssl_iostream_context_ref(struct ssl_iostream_context *ctx)
{
	i_assert(ctx->refcount > 0);
	ctx->refcount++;
}

void openssl_iostream_context_unref(struct ssl_iostream_context *ctx)
{
	i_assert(ctx->refcount > 0);
	if (--ctx->refcount > 0)
		return;

	SSL_CTX_free(ctx->ssl_ctx);
	pool_unref(&ctx->pool);
	i_free(ctx);
}

void openssl_iostream_global_deinit(void)
{
	if (!ssl_global_initialized)
		return;
	dovecot_openssl_common_global_unref();
}

int openssl_iostream_global_init(const struct ssl_iostream_settings *set,
				 const char **error_r)
{
	static char dovecot[] = "dovecot";
	const char *error;

	if (ssl_global_initialized)
		return 0;

	ssl_global_initialized = TRUE;
	dovecot_openssl_common_global_ref();

	dovecot_ssl_extdata_index =
		SSL_get_ex_new_index(0, dovecot, NULL, NULL, NULL);

	if (set->crypto_device != NULL && *set->crypto_device != '\0') {
		switch (dovecot_openssl_common_global_set_engine(set->crypto_device, &error)) {
		case 0:
			error = t_strdup_printf(
				"Unknown ssl_crypto_device: %s",
				set->crypto_device);
			/* fall through */
		case -1:
			*error_r = error;
			/* we'll deinit at exit in any case */
			return -1;
		}
	}
	return 0;
}
