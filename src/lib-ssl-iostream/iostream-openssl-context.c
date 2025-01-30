/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "connection.h"
#include "hex-binary.h"
#include "safe-memset.h"
#include "iostream-openssl.h"
#include "dovecot-openssl-common.h"

#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>

#define ALPN_MAX_PROTOCOLS 10

struct ssl_iostream_password_context {
	const char *password;
	const char *error;
};

static bool ssl_global_initialized = FALSE;
int dovecot_ssl_extdata_index;

#ifdef SSL_CTX_set_tmp_dh_callback
static DH *ssl_tmp_dh_callback(SSL *ssl,
			       int is_export ATTR_UNUSED, int keylength ATTR_UNUSED)
{
	struct ssl_iostream *ssl_io =
		SSL_get_ex_data(ssl, dovecot_ssl_extdata_index);

	e_error(ssl_io->event, "Diffie-Hellman key exchange requested, "
		"but no DH parameters provided. Set ssl_server_dh_file=/path/to/dh.pem");
	return NULL;
}
#endif

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

static int
openssl_iostream_load_key(struct ssl_iostream_context *ssl_ctx,
			  const struct ssl_iostream_cert *set,
			  const char *set_name,
			  EVP_PKEY **pkey_r, const char **error_r)
{
	struct ssl_iostream_password_context ctx;
	EVP_PKEY *pkey;
	BIO *bio;

	bio = BIO_new_mem_buf(set->key.content, strlen(set->key.content));
	if (bio == NULL) {
		*error_r = t_strdup_printf("BIO_new_mem_buf() failed: %s",
					   openssl_iostream_error());
		return -1;
	}

	ctx.password = set->key_password;
	ctx.error = NULL;

	pkey = PEM_read_bio_PrivateKey(bio, NULL, pem_password_callback, &ctx);
	if (pkey == NULL && ctx.error == NULL) {
		string_t *str = t_str_new(128);
		str_printfa(str, "Couldn't parse private SSL key (%s setting)",
			    set_name);
		if (ctx.password != NULL) {
			str_printfa(str, " (maybe %s is wrong?)",
				    ssl_ctx->client_ctx ?
				    "ssl_client_key_password" :
				    "ssl_server_key_password");
		}
		str_printfa(str, ": %s", openssl_iostream_error());
		ctx.error = str_c(str);
	}
	BIO_free(bio);

	*pkey_r = pkey;
	*error_r = ctx.error;
	return pkey == NULL ? -1 : 0;
}

static
int openssl_iostream_load_dh(const struct ssl_iostream_settings *set,
			     EVP_PKEY **pkey_r, const char **error_r)
{
	BIO *bio;
	EVP_PKEY *pkey = NULL;

	bio = BIO_new_mem_buf(set->dh.content, strlen(set->dh.content));

	if (bio == NULL) {
		*error_r = t_strdup_printf("BIO_new_mem_buf() failed: %s",
					   openssl_iostream_error());
		return -1;
	}

	if ((pkey = PEM_read_bio_Parameters(bio, &pkey)) == NULL) {
		*error_r = t_strdup_printf("Couldn't parse DH parameters: %s",
					   openssl_iostream_error());
	}

	BIO_free(bio);
	*pkey_r = pkey;
	return pkey == NULL ? -1 : 0;
}

static int
ssl_iostream_ctx_use_key(struct ssl_iostream_context *ctx, const char *set_name,
			 const struct ssl_iostream_cert *set,
			 const char **error_r)
{
	EVP_PKEY *pkey;
	int ret = 0;

	if (openssl_iostream_load_key(ctx, set, set_name, &pkey, error_r) < 0)
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
	EVP_PKEY *pkey_dh;
	int ret = 0;
	if (*set->dh.content == '\0') {
		return 0;
	}
	if (openssl_iostream_load_dh(set, &pkey_dh, error_r) < 0)
		return -1;
#ifdef HAVE_SSL_CTX_set0_tmp_dh_pkey
	if (SSL_CTX_set0_tmp_dh_pkey(ctx->ssl_ctx, pkey_dh) == 0)
#else
	DH *dh = EVP_PKEY_get0_DH(pkey_dh);
	if (SSL_CTX_set_tmp_dh(ctx->ssl_ctx, dh) == 0)
#endif
	{
		 *error_r = t_strdup_printf(
			"Can't load DH parameters (ssl_server_dh_file setting): %s",
			openssl_iostream_key_load_error());
		ret = -1;
	}
#ifndef HAVE_SSL_CTX_set0_tmp_dh_pkey
	EVP_PKEY_free(pkey_dh);
#endif
	return ret;
}

static int ssl_ctx_use_certificate_chain(SSL_CTX *ctx, const char *cert)
{
	/* mostly just copy&pasted from SSL_CTX_use_certificate_chain_file() */
	BIO *in;
	X509 *x;
	int ret = 0;

	in = BIO_new_mem_buf(cert, strlen(cert));
	if (in == NULL)
		i_fatal("BIO_new_mem_buf() failed");

	x = PEM_read_bio_X509(in, NULL, NULL, NULL);
	if (x == NULL)
		goto end;

	ret = SSL_CTX_use_certificate(ctx, x);
	if (ERR_peek_error() != 0)
		ret = 0;

	if (ret != 0) {
#ifdef HAVE_SSL_CTX_select_current_cert
		SSL_CTX_select_current_cert(ctx, x);
#endif
		/* If we could set up our certificate, now proceed to
		 * the CA certificates.
		 */
		X509 *ca;
		int r;
		unsigned long err;

		while ((ca = PEM_read_bio_X509(in,NULL,NULL,NULL)) != NULL) {
			r = SSL_CTX_add0_chain_cert(ctx, ca);
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

	bio = BIO_new_mem_buf(ca, strlen(ca));
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
load_ca_locations(struct ssl_iostream_context *ctx,
		  const char *ca_dir, const char **error_r)
{
	if (SSL_CTX_load_verify_locations(ctx->ssl_ctx, NULL, ca_dir) != 0)
		return 0;

	*error_r = t_strdup_printf("Can't load CA certs from directory %s "
				   "(ssl_client_ca_dir setting): %s",
				   ca_dir, openssl_iostream_error());
	return -1;
}

static void
ssl_iostream_ctx_verify_remote_cert(struct ssl_iostream_context *ctx,
				    const struct ssl_iostream_settings *set,
				    STACK_OF(X509_NAME) *ca_names)
{
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
	if (!set->skip_crl_check) {
		X509_STORE *store;

		store = SSL_CTX_get_cert_store(ctx->ssl_ctx);
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
				     X509_V_FLAG_CRL_CHECK_ALL);
	}
#endif

	SSL_CTX_set_client_CA_list(ctx->ssl_ctx, ca_names);
}

static int ssl_servername_process(struct ssl_iostream *ssl_io, const char *host,
				  int *al)
{
	const char *error;

	i_free(ssl_io->sni_host);
	if (host != NULL && !connection_is_valid_dns_name(host)) {
		openssl_iostream_set_error(ssl_io,
			"TLS SNI servername sent by client is not a valid DNS name");
		*al = SSL_AD_UNRECOGNIZED_NAME;
		return -1;
	}
	ssl_io->sni_host = i_strdup(host);

	if (ssl_io->sni_callback != NULL) {
		if (ssl_io->sni_callback(ssl_io->sni_host, &error,
					 ssl_io->sni_context) < 0) {
			e_error(ssl_io->event, "%s", error);
			openssl_iostream_set_error(ssl_io, error);
			*al = SSL_AD_INTERNAL_ERROR;
			return -1;
		}
	}

	return 0;
}

#ifndef HAVE_SSL_client_hello_get0_ciphers

static int ssl_servername_callback(SSL *ssl, int *al,
				   void *context ATTR_UNUSED)
{
	struct ssl_iostream *ssl_io;
	const char *host;

	ssl_io = SSL_get_ex_data(ssl, dovecot_ssl_extdata_index);
	host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

	if (ssl_servername_process(ssl_io, host, al) < 0)
		return SSL_TLSEXT_ERR_ALERT_FATAL;

	return SSL_TLSEXT_ERR_OK;
}

#else

static const int ssl_ja3_grease[] = {
	0x0a0a,
	0x1a1a,
	0x2a2a,
	0x3a3a,
	0x4a4a,
	0x5a5a,
	0x6a6a,
	0x7a7a,
	0x8a8a,
	0x9a9a,
	0xaaaa,
	0xbaba,
	0xcaca,
	0xdada,
	0xeaea,
	0xfafa,
};

static bool
ssl_ja3_is_ext_greased(int id)
{
	for (size_t i = 0; i < N_ELEMENTS(ssl_ja3_grease); ++i)
		if (id == ssl_ja3_grease[i])
			return TRUE;
	return FALSE;
}

static const int ssl_ja3_nid_list[] = {
	NID_sect163k1,        /* sect163k1 (1) */
	NID_sect163r1,        /* sect163r1 (2) */
	NID_sect163r2,        /* sect163r2 (3) */
	NID_sect193r1,        /* sect193r1 (4) */
	NID_sect193r2,        /* sect193r2 (5) */
	NID_sect233k1,        /* sect233k1 (6) */
	NID_sect233r1,        /* sect233r1 (7) */
	NID_sect239k1,        /* sect239k1 (8) */
	NID_sect283k1,        /* sect283k1 (9) */
	NID_sect283r1,        /* sect283r1 (10) */
	NID_sect409k1,        /* sect409k1 (11) */
	NID_sect409r1,        /* sect409r1 (12) */
	NID_sect571k1,        /* sect571k1 (13) */
	NID_sect571r1,        /* sect571r1 (14) */
	NID_secp160k1,        /* secp160k1 (15) */
	NID_secp160r1,        /* secp160r1 (16) */
	NID_secp160r2,        /* secp160r2 (17) */
	NID_secp192k1,        /* secp192k1 (18) */
	NID_X9_62_prime192v1, /* secp192r1 (19) */
	NID_secp224k1,        /* secp224k1 (20) */
	NID_secp224r1,        /* secp224r1 (21) */
	NID_secp256k1,        /* secp256k1 (22) */
	NID_X9_62_prime256v1, /* secp256r1 (23) */
	NID_secp384r1,        /* secp384r1 (24) */
	NID_secp521r1,        /* secp521r1 (25) */
	NID_brainpoolP256r1,  /* brainpoolP256r1 (26) */
	NID_brainpoolP384r1,  /* brainpoolP384r1 (27) */
	NID_brainpoolP512r1,  /* brainpool512r1 (28) */
	NID_X25519,           /* X25519 (29) */
	NID_X448,             /* X448 (30) */
};

static int ssl_ja3_nid_to_cid(int nid)
{
	for (size_t i = 0; i < N_ELEMENTS(ssl_ja3_nid_list); i++)
		if (nid == ssl_ja3_nid_list[i])
			return ((int)i)+1;

	if (nid == NID_ffdhe2048)
		return 0x100;
	else if (nid == NID_ffdhe3072)
		return 0x101;
	else if (nid == NID_ffdhe4096)
		return 0x102;
	else if (nid == NID_ffdhe6144)
		return 0x103;
	else if (nid == NID_ffdhe8192)
	        return 0x104;
	return nid;
}

static const char *extract_server_name(const unsigned char *ext, size_t extlen)
{
	/* must have two byte veclen, two bytes for
	   index and type, and two bytes for length
	   and actual name. */
	if (extlen < 2 + 2 + 2)
		return NULL;
	/* Vector length first */
	unsigned short veclen = be16_to_cpu_unaligned(ext);
	if (veclen + 2U != extlen)
		return NULL;
	ext += 2;
	extlen -= 2;
	/* Expecting only host_name as first ServerName,
	   we also only support max 255 character host names,
	   so if the first byte of the length is non-zero,
	   reject as well. */
	if (ext[0] != TLSEXT_NAMETYPE_host_name || ext[1] != 0)
		return NULL;
	ext += 2;
	extlen -= 2;
	unsigned char namelen = ext[0];
	if (namelen > extlen - 1)
		return NULL;
	return t_strdup_until(ext + 1, ext + 1 + namelen);
}

static int ssl_clienthello_callback(SSL *ssl, int *al,
				    void *context ATTR_UNUSED)
{
	struct ssl_iostream *ssl_io =
		SSL_get_ex_data(ssl, dovecot_ssl_extdata_index);

	int ver = SSL_version(ssl)-1;
	const unsigned char *ciphers = NULL;
	size_t nciphers = 0;
	string_t *ja3 = t_str_new(64);

	str_printfa(ja3, "%d,", ver);
	nciphers = SSL_client_hello_get0_ciphers(ssl, &ciphers);

	for (size_t i = 0; i < nciphers; i += 2) {
		if (i > 0)
			str_append_c(ja3, '-');
		uint16_t cipher = be16_to_cpu_unaligned(&ciphers[i]);
		str_printfa(ja3, "%u", cipher);
	}
	str_append_c(ja3, ',');

	int *exts = NULL;
	size_t nexts = 0;
	if (SSL_client_hello_get1_extensions_present(ssl, &exts, &nexts) == 1) {
		bool first = TRUE;
		for (size_t i = 0; i < nexts; i++) {
			if (ssl_ja3_is_ext_greased(exts[i]))
				continue;
			if (first)
				first = FALSE;
			else
				str_append_c(ja3, '-');
			str_printfa(ja3, "%d", exts[i]);
		}
		OPENSSL_free(exts);
	}
	str_append_c(ja3, ',');

	const unsigned char *ext = NULL;
	size_t extlen;

	/* Process extension 10 - groups */
	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_supported_groups,
				      &ext, &extlen) == 1 &&
	    extlen > 0) {
		bool first = TRUE;
		unsigned short veclen = be16_to_cpu_unaligned(ext);
		if (veclen+2U == extlen) {
			for (size_t i = 2; i < extlen; i+=2) {
				uint16_t group = be16_to_cpu_unaligned(&ext[i]);
				if (ssl_ja3_is_ext_greased(group))
					continue;
				if (first)
					first = FALSE;
				else
					str_append_c(ja3, '-');
				str_printfa(ja3, "%u", ssl_ja3_nid_to_cid(group));
			}
		}
	}
	str_append_c(ja3, ',');

	/* Process extension 11 - ec point formats */
	ext = NULL;
	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_ec_point_formats,
				      &ext, &extlen) == 1 &&
	    extlen > 0 && extlen == ext[0]+1U) {
		for (size_t i = 1; i < extlen; i++) {
			if (i > 1)
				str_append_c(ja3, '-');
			str_printfa(ja3, "%u", ext[i]);
		}
	}

	/* Store ja3 string */
	i_free(ssl_io->ja3_str);
	ssl_io->ja3_str = i_strdup(str_c(ja3));

	/* Process extension 0 - server_name */
	const char *host = NULL;
	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name,
				      &ext, &extlen) == 1 &&
	    extlen > 0)
		host = extract_server_name(ext, extlen);

	/* host can be NULL, but that's ok. */
	if (ssl_servername_process(ssl_io, host, al) < 0)
		return SSL_CLIENT_HELLO_ERROR;

	return SSL_CLIENT_HELLO_SUCCESS;
}

#endif

#if defined(HAVE_SSL_CTX_set_alpn_select_cb)
static int
openssl_iostream_alpn_select(SSL *ssl ATTR_UNUSED, const unsigned char **out,
			     unsigned char *outlen, const unsigned char *in,
			     unsigned int inlen, void *arg)
{
	struct ssl_iostream_context *ctx = arg;
	ARRAY(struct ssl_alpn_protocol) in_protos;
	const unsigned char *end = in + inlen;
	const struct ssl_alpn_protocol *in_proto, *proto;
	size_t count_in = 0;

	t_array_init(&in_protos, 1);

	if (ctx->protos == NULL) {
		/* nothing available */
		return SSL_TLSEXT_ERR_NOACK;
	}

	/* allow max 10 protocols */
	while (in < end && count_in < ALPN_MAX_PROTOCOLS)
	{
		unsigned char len = *in;
		if (in + len > end)
			return SSL_TLSEXT_ERR_ALERT_FATAL;
		in++;
		struct ssl_alpn_protocol *value = array_append_space(&in_protos);
		/* Normalize protocol into lowercase string, and ensure it does
		   not contain NUL bytes. */
		const char *proto = t_str_lcase(t_strndup(in, len));
		value->proto = (const unsigned char *)proto;
		value->proto_len = strlen(proto);
		in += len;
		count_in++;
	}

	array_foreach(&in_protos, in_proto) {
		for (proto = ctx->protos; proto->proto != NULL; proto++) {
			if (in_proto->proto_len == proto->proto_len &&
			    memcmp(in_proto->proto, proto->proto, proto->proto_len) == 0) {
				*out = proto->proto;
				*outlen = proto->proto_len;
				return SSL_TLSEXT_ERR_OK;
			}
		}
	}

	return SSL_TLSEXT_ERR_ALERT_FATAL;
}
#endif


static int
ssl_iostream_context_load_ca(struct ssl_iostream_context *ctx,
			     const struct ssl_iostream_settings *set,
			     const char **error_r)
{
	X509_STORE *store;
	STACK_OF(X509_NAME) *xnames = NULL;
	bool have_ca = FALSE;

	if (set->ca.content != NULL && set->ca.content[0] != '\0') {
		store = SSL_CTX_get_cert_store(ctx->ssl_ctx);
		if (load_ca(store, set->ca.content, &xnames) < 0) {
			*error_r = t_strdup_printf(
				"Couldn't parse %s: %s", ctx->client_ctx ?
				"ssl_client_ca_file" : "ssl_server_ca_file",
				openssl_iostream_error());
			return -1;
		}
		ssl_iostream_ctx_verify_remote_cert(ctx, set, xnames);
		have_ca = TRUE;
	}
	if (set->ca_dir != NULL && *set->ca_dir != '\0') {
		if (load_ca_locations(ctx, set->ca_dir, error_r) < 0)
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
		*error_r = "Can't verify remote client certs without CA (ssl_server_ca_file setting)";
		return -1;
	}
	return 0;
}

static int
ssl_iostream_context_set(struct ssl_iostream_context *ctx,
			 const struct ssl_iostream_settings *set,
			 const char **error_r)
{
	ctx->verify_remote_cert = set->verify_remote_cert;
	ctx->allow_invalid_cert = set->allow_invalid_cert;

	if (set->cipher_list != NULL && set->cipher_list[0] != '\0' &&
	    SSL_CTX_set_cipher_list(ctx->ssl_ctx, set->cipher_list) == 0) {
		*error_r = t_strdup_printf(
			"Can't set cipher list to '%s' (ssl_cipher_list setting): %s",
			set->cipher_list, openssl_iostream_error());
		return -1;
	}
	if (set->curve_list != NULL && strlen(set->curve_list) > 0 &&
		SSL_CTX_set1_curves_list(ctx->ssl_ctx, set->curve_list) == 0) {
		*error_r = t_strdup_printf(
			"Can't set curve list to '%s' (ssl_curve_list setting): %s",
			set->curve_list, openssl_iostream_error());
		return -1;
	}
	if (set->ciphersuites != NULL && set->ciphersuites[0] != '\0' &&
	    SSL_CTX_set_ciphersuites(ctx->ssl_ctx, set->ciphersuites) == 0) {
		*error_r = t_strdup_printf(
			"Can't set ciphersuites to '%s' (ssl_cipher_suites setting): %s",
			set->ciphersuites, openssl_iostream_error());
		return -1;
	}
	if (set->prefer_server_ciphers) {
		SSL_CTX_set_options(ctx->ssl_ctx,
				    SSL_OP_CIPHER_SERVER_PREFERENCE);
	}
	if (set->min_protocol != NULL && set->min_protocol[0] != '\0') {
		long opts;
		int min_protocol;
		if (openssl_min_protocol_to_options(set->min_protocol,
						    &opts, &min_protocol) < 0) {
			*error_r = t_strdup_printf(
				"Can't set minimum protocol to '%s' "
				"(ssl_min_protocol setting): Unknown value",
				set->min_protocol);
			return -1;
		}
		SSL_CTX_set_min_proto_version(ctx->ssl_ctx, min_protocol);
	}

	/* Client can ignore an empty ssl_client_cert_file, but server will fail
	   if ssl_server_cert_file is empty. */
	if (set->cert.cert.content != NULL &&
	    (set->cert.cert.content[0] != '\0' || !ctx->client_ctx) &&
	    ssl_ctx_use_certificate_chain(ctx->ssl_ctx, set->cert.cert.content) == 0) {
		*error_r = t_strdup_printf(
			"Can't load SSL certificate (%s setting): %s",
			ctx->client_ctx ? "ssl_client_cert_file" :
			"ssl_server_cert_file",
			openssl_iostream_use_certificate_error(set->cert.cert.content));
		return -1;
	}
	if (set->cert.key.content != NULL && set->cert.key.content[0] != '\0') {
		if (ssl_iostream_ctx_use_key(ctx, ctx->client_ctx ?
					     "ssl_client_key_file" :
					     "ssl_server_key_file",
					     &set->cert, error_r) < 0)
			return -1;
	}
	if (set->alt_cert.cert.content != NULL &&
	    set->alt_cert.cert.content[0] != '\0' &&
	    ssl_ctx_use_certificate_chain(ctx->ssl_ctx, set->alt_cert.cert.content) == 0) {
		*error_r = t_strdup_printf(
			"Can't load alternative SSL certificate "
			"(ssl_server_alt_cert_file setting): %s",
			openssl_iostream_use_certificate_error(set->alt_cert.cert.content));
		return -1;
	}
	if (set->alt_cert.key.content != NULL &&
	    set->alt_cert.key.content[0] != '\0') {
		if (ssl_iostream_ctx_use_key(ctx, "ssl_server_alt_key_file",
					     &set->alt_cert, error_r) < 0)
			return -1;
	}

	if (set->dh.content != NULL && *set->dh.content != '\0') {
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
				"Invalid ssl_server_cert_username_field: %s",
				set->cert_username_field);
			return -1;
		}
	}
	if (!ctx->client_ctx) {
#ifdef HAVE_SSL_client_hello_get0_ciphers
		SSL_CTX_set_client_hello_cb(ctx->ssl_ctx, ssl_clienthello_callback, ctx);
#else
		if (SSL_CTX_set_tlsext_servername_callback(ctx->ssl_ctx,
					ssl_servername_callback) != 1)
			i_unreached();
#endif
#ifdef HAVE_SSL_CTX_set_alpn_select_cb
		SSL_CTX_set_alpn_select_cb(ctx->ssl_ctx, openssl_iostream_alpn_select, ctx);
#endif
	}
	if (ctx->protos == NULL && set->application_protocols != NULL) {
		openssl_iostream_context_set_application_protocols(ctx,
			set->application_protocols);
	}
	return 0;
}

static int
ssl_proxy_ctx_set_crypto_params(SSL_CTX *ssl_ctx,
				const struct ssl_iostream_settings *set ATTR_UNUSED,
				const char **error_r ATTR_UNUSED)
{
#ifdef SSL_CTX_set_tmp_dh_callback
	if (set->dh.content == NULL || *set->dh.content == '\0')
		SSL_CTX_set_tmp_dh_callback(ssl_ctx, ssl_tmp_dh_callback);
#endif
	/* In the non-recommended situation where ECDH cipher suites are being
	   used instead of ECDHE, do not reuse the same ECDH key pair for
	   different sessions. This option improves forward secrecy. */
	SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
	/* Improves forward secrecy with DH parameters, especially if the
	   parameters used aren't strong primes. See OpenSSL manual. */
	SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);
	return 0;
}

void openssl_iostream_context_set_application_protocols(struct ssl_iostream_context *ctx,
							const char *const *names)
{
	i_assert(ctx->protos == NULL);
	i_assert(names != NULL);
	ARRAY(struct ssl_alpn_protocol) protos;
	p_array_init(&protos, ctx->pool, str_array_length(names) + 1);
	for (; *names != NULL; names++) {
		struct ssl_alpn_protocol *proto = array_append_space(&protos);
		proto->proto_len = strlen(*names);
		i_assert(proto->proto_len <= UINT8_MAX);
		proto->proto = p_memdup(ctx->pool, *names, proto->proto_len);
	}
	array_append_zero(&protos);
	ctx->protos = array_front(&protos);
#ifdef HAVE_SSL_CTX_set_alpn_select_cb
	if (ctx->client_ctx) {
		buffer_t *protos = buffer_create_dynamic(ctx->pool, 32);
		for (size_t i = 0; ctx->protos[i].proto != NULL; i++) {
			unsigned char len = ctx->protos[i].proto_len;
			buffer_append_c(protos, len);
			buffer_append(protos, ctx->protos[i].proto, len);
		}
		SSL_CTX_set_alpn_protos(ctx->ssl_ctx, protos->data, protos->used);
	}
#endif
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
	else
		SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_COMPRESSION);
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
