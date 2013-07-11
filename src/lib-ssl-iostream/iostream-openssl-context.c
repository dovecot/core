/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "safe-memset.h"
#include "iostream-openssl.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

struct ssl_iostream_password_context {
	const char *password;
	const char *error;
};

static bool ssl_global_initialized = FALSE;
static ENGINE *ssl_iostream_engine;
int dovecot_ssl_extdata_index;

static int ssl_iostream_init_global(const struct ssl_iostream_settings *set,
				    const char **error_r);

const char *openssl_iostream_error(void)
{
	unsigned long err;
	char *buf;
	size_t err_size = 256;

	err = ERR_get_error();
	if (err == 0) {
		if (errno != 0)
			return strerror(errno);
		return "Unknown error";
	}
	if (ERR_GET_REASON(err) == ERR_R_MALLOC_FAILURE)
		i_fatal_status(FATAL_OUTOFMEM, "OpenSSL malloc() failed");

	buf = t_malloc(err_size);
	buf[err_size-1] = '\0';
	ERR_error_string_n(err, buf, err_size-1);
	return buf;
}

const char *openssl_iostream_key_load_error(void)
{
       unsigned long err = ERR_peek_error();

       if (ERR_GET_LIB(err) == ERR_LIB_X509 &&
           ERR_GET_REASON(err) == X509_R_KEY_VALUES_MISMATCH)
               return "Key is for a different cert than ssl_cert";
       else
               return openssl_iostream_error();
}

static RSA *ssl_gen_rsa_key(SSL *ssl ATTR_UNUSED,
			    int is_export ATTR_UNUSED, int keylength)
{
	return RSA_generate_key(keylength, RSA_F4, NULL, NULL);
}

static DH *ssl_tmp_dh_callback(SSL *ssl ATTR_UNUSED,
			       int is_export, int keylength)
{
	struct ssl_iostream *ssl_io;

	ssl_io = SSL_get_ex_data(ssl, dovecot_ssl_extdata_index);
	/* Well, I'm not exactly sure why the logic in here is this.
	   It's the same as in Postfix, so it can't be too wrong. */
	if (is_export && keylength == 512 && ssl_io->ctx->dh_512 != NULL)
		return ssl_io->ctx->dh_512;
	else
		return ssl_io->ctx->dh_1024;
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

	if (i_strocpy(buf, userdata, size) < 0) {
		ctx->error = "SSL private key password is too long";
		return 0;
	}
	return strlen(buf);
}

int openssl_iostream_load_key(const struct ssl_iostream_settings *set,
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
		ctx.error = t_strdup_printf("Couldn't parse private SSL key: %s",
					    openssl_iostream_error());
	}
	BIO_free(bio);

	safe_memset(key, 0, strlen(key));
	*pkey_r = pkey;
	*error_r = ctx.error;
	return pkey == NULL ? -1 : 0;
}

static int
ssl_iostream_ctx_use_key(struct ssl_iostream_context *ctx,
			 const struct ssl_iostream_settings *set,
			 const char **error_r)
{
	EVP_PKEY *pkey;
	int ret = 0;

	if (openssl_iostream_load_key(set, &pkey, error_r) < 0)
		return -1;
	if (!SSL_CTX_use_PrivateKey(ctx->ssl_ctx, pkey)) {
		*error_r = t_strdup_printf(
			"Can't load SSL private key: %s",
			openssl_iostream_key_load_error());
		ret = -1;
	}
	EVP_PKEY_free(pkey);
	return ret;
}

static bool is_pem_key(const char *cert)
{
	return strstr(cert, "PRIVATE KEY---") != NULL;
}

const char *ssl_iostream_get_use_certificate_error(const char *cert)
{
	unsigned long err;

	err = ERR_peek_error();
	if (ERR_GET_LIB(err) != ERR_LIB_PEM ||
	    ERR_GET_REASON(err) != PEM_R_NO_START_LINE)
		return openssl_iostream_error();
	else if (is_pem_key(cert)) {
		return "The file contains a private key "
			"(you've mixed ssl_cert and ssl_key settings)";
	} else {
		return "There is no certificate.";
	}
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
		/* If we could set up our certificate, now proceed to
		 * the CA certificates.
		 */
		X509 *ca;
		int r;
		unsigned long err;
		
		while ((ca = PEM_read_bio_X509(in,NULL,NULL,NULL)) != NULL) {
			r = SSL_CTX_add_extra_chain_cert(ctx, ca);
			if (!r) {
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
		if(itmp->x509) {
			X509_STORE_add_cert(store, itmp->x509);
			xname = X509_get_subject_name(itmp->x509);
			if (xname != NULL)
				xname = X509_NAME_dup(xname);
			if (xname != NULL)
				sk_X509_NAME_push(xnames, xname);
		}
		if(itmp->crl)
			X509_STORE_add_crl(store, itmp->crl);
	}
	sk_X509_INFO_pop_free(inf, X509_INFO_free);
	*xnames_r = xnames;
	return 0;
}

static void
ssl_iostream_ctx_verify_remote_cert(struct ssl_iostream_context *ctx,
				    STACK_OF(X509_NAME) *ca_names)
{
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
	X509_STORE *store;

	store = SSL_CTX_get_cert_store(ctx->ssl_ctx);
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
			     X509_V_FLAG_CRL_CHECK_ALL);
#endif

	SSL_CTX_set_client_CA_list(ctx->ssl_ctx, ca_names);
}

static struct ssl_iostream_settings *
ssl_iostream_settings_dup(pool_t pool,
			  const struct ssl_iostream_settings *old_set)
{
	struct ssl_iostream_settings *new_set;

	new_set = p_new(pool, struct ssl_iostream_settings, 1);
	new_set->protocols = p_strdup(pool, old_set->protocols);
	new_set->cipher_list = p_strdup(pool, old_set->cipher_list);
	new_set->cert = p_strdup(pool, old_set->cert);
	new_set->key = p_strdup(pool, old_set->key);
	new_set->key_password = p_strdup(pool, old_set->key_password);

	new_set->verbose = old_set->verbose;
	return new_set;
}

#ifdef HAVE_SSL_GET_SERVERNAME
static int ssl_servername_callback(SSL *ssl, int *al ATTR_UNUSED,
				   void *context ATTR_UNUSED)
{
	struct ssl_iostream *ssl_io;
	const char *host;

	ssl_io = SSL_get_ex_data(ssl, dovecot_ssl_extdata_index);
	host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (SSL_get_servername_type(ssl) != -1) {
		i_free(ssl_io->host);
		ssl_io->host = i_strdup(host);
	} else if (ssl_io->verbose) {
		i_debug("SSL_get_servername() failed");
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
		if (!SSL_CTX_load_verify_locations(ctx->ssl_ctx, ca_file, ca_dir)) {
			*error_r = t_strdup_printf(
				"Can't load CA certs from directory %s: %s",
				set->ca_dir, openssl_iostream_error());
			return -1;
		}
		have_ca = TRUE;
	}

	if (!have_ca) {
		*error_r = "Can't verify remote certs without CA";
		return -1;
	}
	return 0;
}

static int
ssl_iostream_context_set(struct ssl_iostream_context *ctx,
			 const struct ssl_iostream_settings *set,
			 const char **error_r)
{
	ctx->set = ssl_iostream_settings_dup(ctx->pool, set);
	if (set->cipher_list != NULL &&
	    !SSL_CTX_set_cipher_list(ctx->ssl_ctx, set->cipher_list)) {
		*error_r = t_strdup_printf("Can't set cipher list to '%s': %s",
			set->cipher_list, openssl_iostream_error());
		return -1;
	}
	if (ctx->set->protocols != NULL) {
		SSL_CTX_set_options(ctx->ssl_ctx,
			    openssl_get_protocol_options(ctx->set->protocols));
	}

	if (set->cert != NULL &&
	    ssl_ctx_use_certificate_chain(ctx->ssl_ctx, set->cert) < 0) {
		*error_r = t_strdup_printf("Can't load SSL certificate: %s",
			ssl_iostream_get_use_certificate_error(set->cert));
		return -1;
	}
	if (set->key != NULL) {
		if (ssl_iostream_ctx_use_key(ctx, set, error_r) < 0)
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

#if !defined(OPENSSL_NO_ECDH) && OPENSSL_VERSION_NUMBER >= 0x10000000L && OPENSSL_VERSION_NUMBER < 0x10002000L
static int
ssl_proxy_ctx_get_pkey_ec_curve_name(const struct ssl_iostream_settings *set,
				     int *nid_r, const char **error_r)
{
	int nid = 0;
	EVP_PKEY *pkey;
	EC_KEY *eckey;
	const EC_GROUP *ecgrp;

	if (set->key != NULL) {
		if (openssl_iostream_load_key(set, &pkey, error_r) < 0)
			return -1;

		if ((eckey = EVP_PKEY_get1_EC_KEY(pkey)) != NULL &&
		    (ecgrp = EC_KEY_get0_group(eckey)) != NULL)
			nid = EC_GROUP_get_curve_name(ecgrp);
		EVP_PKEY_free(pkey);
	}

	*nid_r = nid;
	return 0;
}
#endif

static int
ssl_proxy_ctx_set_crypto_params(SSL_CTX *ssl_ctx,
				const struct ssl_iostream_settings *set,
				const char **error_r)
{
#if !defined(OPENSSL_NO_ECDH) && OPENSSL_VERSION_NUMBER >= 0x10000000L && OPENSSL_VERSION_NUMBER < 0x10002000L
	EC_KEY *ecdh;
	int nid;
	const char *curve_name;
#endif
	if (SSL_CTX_need_tmp_RSA(ssl_ctx))
		SSL_CTX_set_tmp_rsa_callback(ssl_ctx, ssl_gen_rsa_key);
	SSL_CTX_set_tmp_dh_callback(ssl_ctx, ssl_tmp_dh_callback);
#if !defined(OPENSSL_NO_ECDH)
	/* In the non-recommended situation where ECDH cipher suites are being
	   used instead of ECDHE, do not reuse the same ECDH key pair for
	   different sessions. This option improves forward secrecy. */
	SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
#endif
#if !defined(OPENSSL_NO_ECDH) && OPENSSL_VERSION_NUMBER >= 0x10002000L
	/* OpenSSL >= 1.0.2 automatically handles ECDH temporary key parameter
	   selection. */
	SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
#elif !defined(OPENSSL_NO_ECDH) && OPENSSL_VERSION_NUMBER >= 0x10000000L
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
	return 0;
}

static int
ssl_iostream_context_init_common(struct ssl_iostream_context *ctx,
				 const struct ssl_iostream_settings *set,
				 const char **error_r)
{
	ctx->pool = pool_alloconly_create("ssl iostream context", 4096);

	/* enable all SSL workarounds, except empty fragments as it
	   makes SSL more vulnerable against attacks */
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv2 |
			    (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS));
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

	if (ssl_iostream_init_global(set, error_r) < 0)
		return -1;
	if ((ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
		*error_r = t_strdup_printf("SSL_CTX_new() failed: %s",
					   openssl_iostream_error());
		return -1;
	}
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

	ctx = i_new(struct ssl_iostream_context, 1);
	ctx->ssl_ctx = ssl_ctx;
	ctx->client_ctx = TRUE;
	if (ssl_iostream_context_init_common(ctx, set, error_r) < 0) {
		ssl_iostream_context_deinit(&ctx);
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

	if (ssl_iostream_init_global(set, error_r) < 0)
		return -1;
	if ((ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
		*error_r = t_strdup_printf("SSL_CTX_new() failed: %s",
					   openssl_iostream_error());
		return -1;
	}

	ctx = i_new(struct ssl_iostream_context, 1);
	ctx->ssl_ctx = ssl_ctx;
	if (ssl_iostream_context_init_common(ctx, set, error_r) < 0) {
		ssl_iostream_context_deinit(&ctx);
		return -1;
	}
	*ctx_r = ctx;
	return 0;
}

void openssl_iostream_context_deinit(struct ssl_iostream_context *ctx)
{
	SSL_CTX_free(ctx->ssl_ctx);
	openssl_iostream_context_free_params(ctx);
	pool_unref(&ctx->pool);
	i_free(ctx);
}

static void ssl_iostream_deinit_global(void)
{
	if (ssl_iostream_engine != NULL)
		ENGINE_finish(ssl_iostream_engine);
	ENGINE_cleanup();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
}

static int ssl_iostream_init_global(const struct ssl_iostream_settings *set,
				    const char **error_r)
{
	static char dovecot[] = "dovecot";
	unsigned char buf;

	if (ssl_global_initialized)
		return 0;

	atexit(ssl_iostream_deinit_global);
	ssl_global_initialized = TRUE;
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	dovecot_ssl_extdata_index =
		SSL_get_ex_new_index(0, dovecot, NULL, NULL, NULL);

	/* PRNG initialization might want to use /dev/urandom, make sure it
	   does it before chrooting. We might not have enough entropy at
	   the first try, so this function may fail. It's still been
	   initialized though. */
	(void)RAND_bytes(&buf, 1);

	if (set->crypto_device != NULL && *set->crypto_device != '\0') {
		ENGINE_load_builtin_engines();
		ssl_iostream_engine = ENGINE_by_id(set->crypto_device);
		if (ssl_iostream_engine == NULL) {
			*error_r = t_strdup_printf(
				"Unknown ssl_crypto_device: %s",
				set->crypto_device);
			ssl_iostream_deinit_global();
			return -1;
		}
		ENGINE_init(ssl_iostream_engine);
		ENGINE_set_default_RSA(ssl_iostream_engine);
		ENGINE_set_default_DSA(ssl_iostream_engine);
		ENGINE_set_default_ciphers(ssl_iostream_engine);
	}
	return 0;
}
