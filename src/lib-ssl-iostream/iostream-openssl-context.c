/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "safe-memset.h"
#include "iostream-openssl.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

struct ssl_iostream_password_context {
	const char *password;
	const char *key_source;
};

static bool ssl_global_initialized = FALSE;
int dovecot_ssl_extdata_index;

static void ssl_iostream_init_global(void);

const char *ssl_iostream_error(void)
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

const char *ssl_iostream_key_load_error(void)
{
       unsigned long err = ERR_peek_error();

       if (ERR_GET_LIB(err) == ERR_LIB_X509 &&
           ERR_GET_REASON(err) == X509_R_KEY_VALUES_MISMATCH)
               return "Key is for a different cert than ssl_cert";
       else
               return ssl_iostream_error();
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
		i_error("%s: SSL private key file is password protected, "
			"but password isn't given", ctx->key_source);
		return 0;
	}

	if (i_strocpy(buf, userdata, size) < 0) {
		i_error("%s: SSL private key password is too long",
			ctx->key_source);
		return 0;
	}
	return strlen(buf);
}

int ssl_iostream_load_key(const struct ssl_iostream_settings *set,
			  const char *key_source, EVP_PKEY **pkey_r)
{
	struct ssl_iostream_password_context ctx;
	EVP_PKEY *pkey;
	BIO *bio;
	char *key;

	key = t_strdup_noconst(set->key);
	bio = BIO_new_mem_buf(key, strlen(key));
	if (bio == NULL) {
		i_error("BIO_new_mem_buf() failed: %s", ssl_iostream_error());
		safe_memset(key, 0, strlen(key));
		return -1;
	}

	ctx.password = set->key_password;
	ctx.key_source = key_source;

	pkey = PEM_read_bio_PrivateKey(bio, NULL, pem_password_callback, &ctx);
	if (pkey == NULL) {
		i_error("%s: Couldn't parse private SSL key: %s",
			key_source, ssl_iostream_error());
	}
	BIO_free(bio);

	safe_memset(key, 0, strlen(key));
	*pkey_r = pkey;
	return pkey == NULL ? -1 : 0;
}

static int
ssl_iostream_ctx_use_key(struct ssl_iostream_context *ctx,
			 const struct ssl_iostream_settings *set)
{
	EVP_PKEY *pkey;
	int ret = 0;

	if (ssl_iostream_load_key(set, ctx->source, &pkey) < 0)
		return -1;
	if (!SSL_CTX_use_PrivateKey(ctx->ssl_ctx, pkey)) {
		i_error("%s: Can't load SSL private key: %s",
			ctx->source, ssl_iostream_key_load_error());
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
		return ssl_iostream_error();
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

static int
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
	return 0;
}

static struct ssl_iostream_settings *
ssl_iostream_settings_dup(pool_t pool,
			  const struct ssl_iostream_settings *old_set)
{
	struct ssl_iostream_settings *new_set;

	new_set = p_new(pool, struct ssl_iostream_settings, 1);
	new_set->cipher_list = p_strdup(pool, old_set->cipher_list);
	new_set->cert = p_strdup(pool, old_set->cert);
	new_set->key = p_strdup(pool, old_set->key);
	new_set->key_password = p_strdup(pool, old_set->key_password);

	new_set->verbose = old_set->verbose;
	return new_set;
}

static int
ssl_iostream_context_set(struct ssl_iostream_context *ctx,
			 const struct ssl_iostream_settings *set)
{
	X509_STORE *store;
	STACK_OF(X509_NAME) *xnames = NULL;

	ctx->set = ssl_iostream_settings_dup(ctx->pool, set);
	if (set->cipher_list != NULL &&
	    !SSL_CTX_set_cipher_list(ctx->ssl_ctx, set->cipher_list)) {
		i_error("%s: Can't set cipher list to '%s': %s",
			ctx->source, set->cipher_list,
			ssl_iostream_error());
		return -1;
	}

	if (set->cert != NULL &&
	    ssl_ctx_use_certificate_chain(ctx->ssl_ctx, set->cert) < 0) {
		i_error("%s: Can't load SSL certificate: %s", ctx->source,
			ssl_iostream_get_use_certificate_error(set->cert));
	}
	if (set->key != NULL) {
		if (ssl_iostream_ctx_use_key(ctx, set) < 0)
			return -1;
	}

	/* set trusted CA certs */
	if (!set->verify_remote_cert) {
		/* no CA */
	} else if (set->ca != NULL) {
		store = SSL_CTX_get_cert_store(ctx->ssl_ctx);
		if (load_ca(store, set->ca, &xnames) < 0) {
			i_error("%s: Couldn't parse ssl_ca: %s", ctx->source,
				ssl_iostream_error());
			return -1;
		}
		if (ssl_iostream_ctx_verify_remote_cert(ctx, xnames) < 0)
			return -1;
	} else if (set->ca_dir != NULL) {
		if (!SSL_CTX_load_verify_locations(ctx->ssl_ctx, NULL,
						   set->ca_dir)) {
			i_error("%s: Can't load CA certs from directory %s: %s",
				ctx->source, set->ca_dir, ssl_iostream_error());
			return -1;
		}
	} else {
		i_error("%s: Can't verify remote certs without CA",
			ctx->source);
		return -1;
	}

	if (set->cert_username_field != NULL) {
		ctx->username_nid = OBJ_txt2nid(set->cert_username_field);
		if (ctx->username_nid == NID_undef) {
			i_error("%s: Invalid cert_username_field: %s",
				ctx->source, set->cert_username_field);
		}
	}
	return 0;
}

static int
ssl_iostream_context_init_common(struct ssl_iostream_context *ctx,
				 const char *source,
				 const struct ssl_iostream_settings *set)
{
	ctx->pool = pool_alloconly_create("ssl iostream context", 4096);
	ctx->source = p_strdup(ctx->pool, source);

	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
	if (SSL_CTX_need_tmp_RSA(ctx->ssl_ctx))
		SSL_CTX_set_tmp_rsa_callback(ctx->ssl_ctx, ssl_gen_rsa_key);
	SSL_CTX_set_tmp_dh_callback(ctx->ssl_ctx, ssl_tmp_dh_callback);

	return ssl_iostream_context_set(ctx, set);
}

int ssl_iostream_context_init_client(const char *source,
				     const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r)
{
	struct ssl_iostream_context *ctx;
	SSL_CTX *ssl_ctx;

	ssl_iostream_init_global();
	if ((ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
		i_error("SSL_CTX_new() failed: %s", ssl_iostream_error());
		return -1;
	}

	ctx = i_new(struct ssl_iostream_context, 1);
	ctx->ssl_ctx = ssl_ctx;
	ctx->client_ctx = TRUE;
	if (ssl_iostream_context_init_common(ctx, source, set) < 0) {
		ssl_iostream_context_deinit(&ctx);
		return -1;
	}
	*ctx_r = ctx;
	return 0;
}

int ssl_iostream_context_init_server(const char *source,
				     const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r)
{
	struct ssl_iostream_context *ctx;
	SSL_CTX *ssl_ctx;

	ssl_iostream_init_global();
	if ((ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
		i_error("SSL_CTX_new() failed: %s", ssl_iostream_error());
		return -1;
	}

	ctx = i_new(struct ssl_iostream_context, 1);
	ctx->ssl_ctx = ssl_ctx;
	if (ssl_iostream_context_init_common(ctx, source, set) < 0) {
		ssl_iostream_context_deinit(&ctx);
		return -1;
	}
	*ctx_r = ctx;
	return 0;
}

void ssl_iostream_context_deinit(struct ssl_iostream_context **_ctx)
{
	struct ssl_iostream_context *ctx = *_ctx;

	*_ctx = NULL;
	SSL_CTX_free(ctx->ssl_ctx);
	ssl_iostream_context_free_params(ctx);
	pool_unref(&ctx->pool);
	i_free(ctx);
}

static void ssl_iostream_deinit_global(void)
{
	EVP_cleanup();
	ERR_free_strings();
}

static void ssl_iostream_init_global(void)
{
	static char dovecot[] = "dovecot";
	unsigned char buf;

	if (ssl_global_initialized)
		return;

	atexit(ssl_iostream_deinit_global);
	ssl_global_initialized = TRUE;
	SSL_library_init();
	SSL_load_error_strings();

	dovecot_ssl_extdata_index =
		SSL_get_ex_new_index(0, dovecot, NULL, NULL, NULL);

	/* PRNG initialization might want to use /dev/urandom, make sure it
	   does it before chrooting. We might not have enough entropy at
	   the first try, so this function may fail. It's still been
	   initialized though. */
	(void)RAND_bytes(&buf, 1);
}
