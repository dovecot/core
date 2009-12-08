/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "ostream.h"
#include "read-full.h"
#include "safe-memset.h"
#include "hash.h"
#include "llist.h"
#include "master-service.h"
#include "master-interface.h"
#include "client-common.h"
#include "ssl-proxy.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef HAVE_OPENSSL

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* Check every 30 minutes if parameters file has been updated */
#define SSL_PARAMFILE_CHECK_INTERVAL (60*30)

#define SSL_PARAMETERS_PATH "ssl-params"

enum ssl_io_action {
	SSL_ADD_INPUT,
	SSL_REMOVE_INPUT,
	SSL_ADD_OUTPUT,
	SSL_REMOVE_OUTPUT
};

struct ssl_proxy {
	int refcount;
	struct ssl_proxy *prev, *next;

	SSL *ssl;
	struct client *client;
	struct ip_addr ip;
	const struct login_settings *set;

	int fd_ssl, fd_plain;
	struct io *io_ssl_read, *io_ssl_write, *io_plain_read, *io_plain_write;

	unsigned char plainout_buf[1024];
	unsigned int plainout_size;

	unsigned char sslout_buf[1024];
	unsigned int sslout_size;

	ssl_handshake_callback_t *handshake_callback;
	void *handshake_context;

	char *last_error;
	unsigned int handshaked:1;
	unsigned int destroyed:1;
	unsigned int cert_received:1;
	unsigned int cert_broken:1;
	unsigned int client_proxy:1;
};

struct ssl_parameters {
	const char *path;
	time_t last_refresh;
	int fd;

	DH *dh_512, *dh_1024;
};

struct ssl_server_context {
	SSL_CTX *ctx;
	pool_t pool;

	const char *cert;
	const char *key;
	const char *ca;
	const char *cipher_list;
	bool verify_client_cert;
};

static int extdata_index;
static struct hash_table *ssl_servers;
static SSL_CTX *ssl_client_ctx;
static unsigned int ssl_proxy_count;
static struct ssl_proxy *ssl_proxies;
static struct ssl_parameters ssl_params;
static int ssl_username_nid;

static void plain_read(struct ssl_proxy *proxy);
static void ssl_read(struct ssl_proxy *proxy);
static void ssl_write(struct ssl_proxy *proxy);
static void ssl_step(struct ssl_proxy *proxy);
static void ssl_proxy_destroy(struct ssl_proxy *proxy);
static void ssl_proxy_unref(struct ssl_proxy *proxy);

static struct ssl_server_context *
ssl_server_context_init(const struct login_settings *set);
static void ssl_server_context_deinit(struct ssl_server_context **_ctx);

static unsigned int ssl_server_context_hash(const void *p)
{
	const struct ssl_server_context *ctx = p;
	unsigned int i, g, h = 0;

	/* checking for different certs is typically good enough,
	   and it should be enough to check only the first few bytes. */
	for (i = 0; i < 16 && ctx->cert[i] != '\0'; i++) {
		h = (h << 4) + ctx->cert[i];
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
	}
	return h;
}

static int ssl_server_context_cmp(const void *p1, const void *p2)
{
	const struct ssl_server_context *ctx1 = p1, *ctx2 = p2;

	if (strcmp(ctx1->cert, ctx2->cert) != 0)
		return 1;
	if (strcmp(ctx1->key, ctx2->key) != 0)
		return 1;
	if (null_strcmp(ctx1->cipher_list, ctx2->cipher_list) != 0)
		return 1;

	return ctx1->verify_client_cert == ctx2->verify_client_cert ? 0 : 1;
}

static void ssl_params_corrupted(void)
{
	i_fatal("Corrupted SSL parameters file: "
		PKG_STATEDIR"/ssl-parameters.dat");
}

static void read_next(struct ssl_parameters *params, void *data, size_t size)
{
	int ret;

	if ((ret = read_full(params->fd, data, size)) < 0)
		i_fatal("read(%s) failed: %m", params->path);
	if (ret == 0)
		ssl_params_corrupted();
}

static bool read_dh_parameters_next(struct ssl_parameters *params)
{
	unsigned char *buf;
	const unsigned char *cbuf;
	unsigned int len;
	int bits;

	/* read bit size. 0 ends the DH parameters list. */
	read_next(params, &bits, sizeof(bits));

	if (bits == 0)
		return FALSE;

	/* read data size. */
	read_next(params, &len, sizeof(len));
	if (len > 1024*100) /* should be enough? */
		ssl_params_corrupted();

	buf = i_malloc(len);
	read_next(params, buf, len);

	cbuf = buf;
	switch (bits) {
	case 512:
		params->dh_512 = d2i_DHparams(NULL, &cbuf, len);
		break;
	case 1024:
		params->dh_1024 = d2i_DHparams(NULL, &cbuf, len);
		break;
	default:
		ssl_params_corrupted();
	}

	i_free(buf);
	return TRUE;
}

static void ssl_free_parameters(struct ssl_parameters *params)
{
	if (params->dh_512 != NULL) {
		DH_free(params->dh_512);
                params->dh_512 = NULL;
	}
	if (params->dh_1024 != NULL) {
		DH_free(params->dh_1024);
                params->dh_1024 = NULL;
	}
}

static void ssl_refresh_parameters(struct ssl_parameters *params)
{
	char c;
	int ret;

	if (params->last_refresh > ioloop_time - SSL_PARAMFILE_CHECK_INTERVAL)
		return;
	params->last_refresh = ioloop_time;

	params->fd = net_connect_unix(params->path);
	if (params->fd == -1) {
		i_error("connect(%s) failed: %m", params->path);
		return;
	}
	net_set_nonblock(params->fd, FALSE);

	ssl_free_parameters(params);
	while (read_dh_parameters_next(params)) ;

	if ((ret = read_full(params->fd, &c, 1)) < 0)
		i_fatal("read(%s) failed: %m", params->path);
	else if (ret != 0) {
		/* more data than expected */
		ssl_params_corrupted();
	}

	if (close(params->fd) < 0)
		i_error("close(%s) failed: %m", params->path);
	params->fd = -1;
}

static void ssl_set_io(struct ssl_proxy *proxy, enum ssl_io_action action)
{
	switch (action) {
	case SSL_ADD_INPUT:
		if (proxy->io_ssl_read != NULL)
			break;
		proxy->io_ssl_read = io_add(proxy->fd_ssl, IO_READ,
					    ssl_step, proxy);
		break;
	case SSL_REMOVE_INPUT:
		if (proxy->io_ssl_read != NULL)
			io_remove(&proxy->io_ssl_read);
		break;
	case SSL_ADD_OUTPUT:
		if (proxy->io_ssl_write != NULL)
			break;
		proxy->io_ssl_write = io_add(proxy->fd_ssl, IO_WRITE,
					     ssl_step, proxy);
		break;
	case SSL_REMOVE_OUTPUT:
		if (proxy->io_ssl_write != NULL)
			io_remove(&proxy->io_ssl_write);
		break;
	}
}

static void plain_block_input(struct ssl_proxy *proxy, bool block)
{
	if (block) {
		if (proxy->io_plain_read != NULL)
			io_remove(&proxy->io_plain_read);
	} else {
		if (proxy->io_plain_read == NULL) {
			proxy->io_plain_read = io_add(proxy->fd_plain, IO_READ,
						      plain_read, proxy);
		}
	}
}

static void plain_read(struct ssl_proxy *proxy)
{
	ssize_t ret;
	bool corked = FALSE;

	if (proxy->sslout_size == sizeof(proxy->sslout_buf)) {
		/* buffer full, block input until it's written */
		plain_block_input(proxy, TRUE);
		return;
	}

	proxy->refcount++;

	while (proxy->sslout_size < sizeof(proxy->sslout_buf) &&
	       !proxy->destroyed) {
		ret = net_receive(proxy->fd_plain,
				  proxy->sslout_buf + proxy->sslout_size,
				  sizeof(proxy->sslout_buf) -
				  proxy->sslout_size);
		if (ret <= 0) {
			if (ret < 0)
				ssl_proxy_destroy(proxy);
			break;
		} else {
			proxy->sslout_size += ret;
			if (!corked) {
				net_set_cork(proxy->fd_ssl, TRUE);
				corked = TRUE;
			}
			ssl_write(proxy);
		}
	}

	if (corked)
		net_set_cork(proxy->fd_ssl, FALSE);

	ssl_proxy_unref(proxy);
}

static void plain_write(struct ssl_proxy *proxy)
{
	ssize_t ret;

	proxy->refcount++;

	ret = net_transmit(proxy->fd_plain, proxy->plainout_buf,
			   proxy->plainout_size);
	if (ret < 0)
		ssl_proxy_destroy(proxy);
	else {
		proxy->plainout_size -= ret;
		memmove(proxy->plainout_buf, proxy->plainout_buf + ret,
			proxy->plainout_size);

		if (proxy->plainout_size > 0) {
			if (proxy->io_plain_write == NULL) {
				proxy->io_plain_write =
					io_add(proxy->fd_plain, IO_WRITE,
					       plain_write, proxy);
			}
		} else {
			if (proxy->io_plain_write != NULL)
				io_remove(&proxy->io_plain_write);
		}

		ssl_set_io(proxy, SSL_ADD_INPUT);
		if (SSL_pending(proxy->ssl) > 0)
			ssl_read(proxy);
	}

	ssl_proxy_unref(proxy);
}

static const char *ssl_err2str(unsigned long err, const char *data, int flags)
{
	const char *ret;
	char *buf;
	size_t err_size = 256;

	buf = t_malloc(err_size);
	buf[err_size-1] = '\0';
	ERR_error_string_n(err, buf, err_size-1);
	ret = buf;

	if ((flags & ERR_TXT_STRING) != 0)
		ret = t_strdup_printf("%s: %s", buf, data);
	return ret;
}

static const char *ssl_last_error(void)
{
	unsigned long err, err2;
	const char *data;
	int flags;

	err = ERR_get_error_line_data(NULL, NULL, &data, &flags);
	while (err != 0 && (err2 = ERR_peek_error()) != 0) {
		i_error("SSL: Stacked error: %s",
			ssl_err2str(err, data, flags));
		err = ERR_get_error();
	}
	if (err == 0) {
		if (errno != 0)
			return strerror(errno);
		return "Unknown error";
	}
	return ssl_err2str(err, data, flags);
}

static void ssl_handle_error(struct ssl_proxy *proxy, int ret,
			     const char *func_name)
{
	const char *errstr = NULL;
	int err;

	proxy->refcount++;

	i_free_and_null(proxy->last_error);
	err = SSL_get_error(proxy->ssl, ret);

	switch (err) {
	case SSL_ERROR_WANT_READ:
		ssl_set_io(proxy, SSL_ADD_INPUT);
		break;
	case SSL_ERROR_WANT_WRITE:
		ssl_set_io(proxy, SSL_ADD_OUTPUT);
		break;
	case SSL_ERROR_SYSCALL:
		/* eat up the error queue */
		if (ERR_peek_error() != 0)
			errstr = ssl_last_error();
		else if (ret != 0)
			errstr = strerror(errno);
		else {
			/* EOF. */
			errstr = "Disconnected";
			break;
		}
		errstr = t_strdup_printf("%s syscall failed: %s",
					 func_name, errstr);
		break;
	case SSL_ERROR_ZERO_RETURN:
		/* clean connection closing */
		ssl_proxy_destroy(proxy);
		break;
	case SSL_ERROR_SSL:
		if (ERR_GET_REASON(ERR_peek_error()) == ERR_R_MALLOC_FAILURE) {
			i_error("OpenSSL malloc() failed. "
				"You may need to increase login_process_size");
		}
		errstr = t_strdup_printf("%s failed: %s",
					 func_name, ssl_last_error());
		break;
	default:
		errstr = t_strdup_printf("%s failed: unknown failure %d (%s)",
					 func_name, err, ssl_last_error());
		break;
	}

	if (errstr != NULL) {
		proxy->last_error = i_strdup(errstr);
		ssl_proxy_destroy(proxy);
	}
	ssl_proxy_unref(proxy);
}

static void ssl_handshake(struct ssl_proxy *proxy)
{
	int ret;

	if (proxy->client_proxy) {
		ret = SSL_connect(proxy->ssl);
		if (ret != 1) {
			ssl_handle_error(proxy, ret, "SSL_connect()");
			return;
		}
	} else {
		ret = SSL_accept(proxy->ssl);
		if (ret != 1) {
			ssl_handle_error(proxy, ret, "SSL_accept()");
			return;
		}
	}
	i_free_and_null(proxy->last_error);
	proxy->handshaked = TRUE;

	ssl_set_io(proxy, SSL_ADD_INPUT);
	plain_block_input(proxy, FALSE);

	if (proxy->handshake_callback != NULL) {
		if (proxy->handshake_callback(proxy->handshake_context) < 0)
			ssl_proxy_destroy(proxy);
	}
}

static void ssl_read(struct ssl_proxy *proxy)
{
	int ret;

	while (proxy->plainout_size < sizeof(proxy->plainout_buf) &&
	       !proxy->destroyed) {
		ret = SSL_read(proxy->ssl,
			       proxy->plainout_buf + proxy->plainout_size,
			       sizeof(proxy->plainout_buf) -
			       proxy->plainout_size);
		if (ret <= 0) {
			ssl_handle_error(proxy, ret, "SSL_read()");
			break;
		} else {
			i_free_and_null(proxy->last_error);
			proxy->plainout_size += ret;
			plain_write(proxy);
		}
	}
}

static void ssl_write(struct ssl_proxy *proxy)
{
	int ret;

	ret = SSL_write(proxy->ssl, proxy->sslout_buf, proxy->sslout_size);
	if (ret <= 0)
		ssl_handle_error(proxy, ret, "SSL_write()");
	else {
		i_free_and_null(proxy->last_error);
		proxy->sslout_size -= ret;
		memmove(proxy->sslout_buf, proxy->sslout_buf + ret,
			proxy->sslout_size);

		ssl_set_io(proxy, proxy->sslout_size > 0 ?
			   SSL_ADD_OUTPUT : SSL_REMOVE_OUTPUT);
		plain_block_input(proxy, FALSE);
	}
}

static void ssl_step(struct ssl_proxy *proxy)
{
	proxy->refcount++;

	if (!proxy->handshaked)
		ssl_handshake(proxy);

	if (proxy->handshaked) {
		if (proxy->plainout_size == sizeof(proxy->plainout_buf))
			ssl_set_io(proxy, SSL_REMOVE_INPUT);
		else
			ssl_read(proxy);

		if (proxy->sslout_size == 0)
			ssl_set_io(proxy, SSL_REMOVE_OUTPUT);
		else {
			net_set_cork(proxy->fd_ssl, TRUE);
			ssl_write(proxy);
			net_set_cork(proxy->fd_ssl, FALSE);
		}
	}

	ssl_proxy_unref(proxy);
}

static int
ssl_proxy_alloc_common(SSL_CTX *ssl_ctx, int fd, const struct ip_addr *ip,
		       const struct login_settings *set,
		       struct ssl_proxy **proxy_r)
{
	struct ssl_proxy *proxy;
	SSL *ssl;
	int sfd[2];

	i_assert(fd != -1);

	*proxy_r = NULL;

	if (!ssl_initialized) {
		i_error("SSL support not enabled in configuration");
		return -1;
	}

	ssl_refresh_parameters(&ssl_params);

	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		i_error("SSL_new() failed: %s", ssl_last_error());
		return -1;
	}

	if (SSL_set_fd(ssl, fd) != 1) {
		i_error("SSL_set_fd() failed: %s", ssl_last_error());
		SSL_free(ssl);
		return -1;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sfd) < 0) {
		i_error("socketpair() failed: %m");
		SSL_free(ssl);
		return -1;
	}

	net_set_nonblock(sfd[0], TRUE);
	net_set_nonblock(sfd[1], TRUE);
	net_set_nonblock(fd, TRUE);

	proxy = i_new(struct ssl_proxy, 1);
	proxy->refcount = 2;
	proxy->ssl = ssl;
	proxy->set = set;
	proxy->fd_ssl = fd;
	proxy->fd_plain = sfd[0];
	proxy->ip = *ip;
        SSL_set_ex_data(ssl, extdata_index, proxy);

	ssl_proxy_count++;
	DLLIST_PREPEND(&ssl_proxies, proxy);

	*proxy_r = proxy;
	return sfd[1];
}

static struct ssl_server_context *
ssl_server_context_get(const struct login_settings *set)
{
	struct ssl_server_context *ctx, lookup_ctx;

	memset(&lookup_ctx, 0, sizeof(lookup_ctx));
	lookup_ctx.cert = set->ssl_cert;
	lookup_ctx.key = set->ssl_key;
	lookup_ctx.ca = set->ssl_ca;
	lookup_ctx.cipher_list = set->ssl_cipher_list;
	lookup_ctx.verify_client_cert = set->ssl_verify_client_cert;

	ctx = hash_table_lookup(ssl_servers, &lookup_ctx);
	if (ctx == NULL)
		ctx = ssl_server_context_init(set);
	return ctx;
}

int ssl_proxy_alloc(int fd, const struct ip_addr *ip,
		    const struct login_settings *set,
		    struct ssl_proxy **proxy_r)
{
	struct ssl_server_context *ctx;

	ctx = ssl_server_context_get(set);
	return ssl_proxy_alloc_common(ctx->ctx, fd, ip, set, proxy_r);
}

int ssl_proxy_client_alloc(int fd, struct ip_addr *ip,
			   const struct login_settings *set,
			   ssl_handshake_callback_t *callback, void *context,
			   struct ssl_proxy **proxy_r)
{
	int ret;

	ret = ssl_proxy_alloc_common(ssl_client_ctx, fd, ip, set, proxy_r);
	if (ret < 0)
		return -1;

	(*proxy_r)->handshake_callback = callback;
	(*proxy_r)->handshake_context = context;
	(*proxy_r)->client_proxy = TRUE;
	return ret;
}

void ssl_proxy_start(struct ssl_proxy *proxy)
{
	ssl_step(proxy);
}

void ssl_proxy_set_client(struct ssl_proxy *proxy, struct client *client)
{
	i_assert(proxy->client == NULL);

	client_ref(client);
	proxy->client = client;
}

bool ssl_proxy_has_valid_client_cert(const struct ssl_proxy *proxy)
{
	return proxy->cert_received && !proxy->cert_broken;
}

bool ssl_proxy_has_broken_client_cert(struct ssl_proxy *proxy)
{
	return proxy->cert_received && proxy->cert_broken;
}

const char *ssl_proxy_get_peer_name(struct ssl_proxy *proxy)
{
	X509 *x509;
	char *name;
	int len;

	if (!ssl_proxy_has_valid_client_cert(proxy))
		return NULL;

	x509 = SSL_get_peer_certificate(proxy->ssl);
	if (x509 == NULL)
		return NULL; /* we should have had it.. */

	len = X509_NAME_get_text_by_NID(X509_get_subject_name(x509),
					ssl_username_nid, NULL, 0);
	if (len < 0)
		name = "";
	else {
		name = t_malloc(len + 1);
		if (X509_NAME_get_text_by_NID(X509_get_subject_name(x509),
					ssl_username_nid, name, len + 1) < 0)
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

bool ssl_proxy_is_handshaked(const struct ssl_proxy *proxy)
{
	return proxy->handshaked;
}

const char *ssl_proxy_get_last_error(const struct ssl_proxy *proxy)
{
	return proxy->last_error;
}

const char *ssl_proxy_get_security_string(struct ssl_proxy *proxy)
{
	SSL_CIPHER *cipher;
#ifdef HAVE_SSL_COMPRESSION
	const COMP_METHOD *comp;
#endif
	int bits, alg_bits;
	const char *comp_str;

	if (!proxy->handshaked)
		return "";

	cipher = SSL_get_current_cipher(proxy->ssl);
	bits = SSL_CIPHER_get_bits(cipher, &alg_bits);
#ifdef HAVE_SSL_COMPRESSION
	comp = SSL_get_current_compression(proxy->ssl);
	comp_str = comp == NULL ? "" :
		t_strconcat(" ", SSL_COMP_get_name(comp), NULL);
#else
	comp_str = "";
#endif
	return t_strdup_printf("%s with cipher %s (%d/%d bits)%s",
			       SSL_get_version(proxy->ssl),
			       SSL_CIPHER_get_name(cipher),
			       bits, alg_bits, comp_str);
}

void ssl_proxy_free(struct ssl_proxy **_proxy)
{
	struct ssl_proxy *proxy = *_proxy;

	*_proxy = NULL;
	ssl_proxy_unref(proxy);
}

static void ssl_proxy_unref(struct ssl_proxy *proxy)
{
	if (--proxy->refcount > 0)
		return;
	i_assert(proxy->refcount == 0);

	SSL_free(proxy->ssl);

	if (proxy->client != NULL)
		client_unref(&proxy->client);
	i_free(proxy);
}

static void ssl_proxy_destroy(struct ssl_proxy *proxy)
{
	if (proxy->destroyed)
		return;
	proxy->destroyed = TRUE;

	ssl_proxy_count--;
	DLLIST_REMOVE(&ssl_proxies, proxy);

	if (proxy->io_ssl_read != NULL)
		io_remove(&proxy->io_ssl_read);
	if (proxy->io_ssl_write != NULL)
		io_remove(&proxy->io_ssl_write);
	if (proxy->io_plain_read != NULL)
		io_remove(&proxy->io_plain_read);
	if (proxy->io_plain_write != NULL)
		io_remove(&proxy->io_plain_write);

	(void)SSL_shutdown(proxy->ssl);

	(void)net_disconnect(proxy->fd_ssl);
	(void)net_disconnect(proxy->fd_plain);

	ssl_proxy_unref(proxy);
}

static RSA *ssl_gen_rsa_key(SSL *ssl ATTR_UNUSED,
			    int is_export ATTR_UNUSED, int keylength)
{
	return RSA_generate_key(keylength, RSA_F4, NULL, NULL);
}

static DH *ssl_tmp_dh_callback(SSL *ssl ATTR_UNUSED,
			       int is_export, int keylength)
{
	/* Well, I'm not exactly sure why the logic in here is this.
	   It's the same as in Postfix, so it can't be too wrong. */
	if (is_export && keylength == 512 && ssl_params.dh_512 != NULL)
		return ssl_params.dh_512;

	return ssl_params.dh_1024;
}

static void ssl_info_callback(const SSL *ssl, int where, int ret)
{
	struct ssl_proxy *proxy;

	proxy = SSL_get_ex_data(ssl, extdata_index);

	if (!proxy->set->verbose_ssl)
		return;

	if ((where & SSL_CB_ALERT) != 0) {
		i_warning("SSL alert: where=0x%x, ret=%d: %s %s [%s]",
			  where, ret, SSL_alert_type_string_long(ret),
			  SSL_alert_desc_string_long(ret),
			  net_ip2addr(&proxy->ip));
	} else {
		i_warning("SSL BIO failed: where=0x%x, ret=%d: %s [%s]",
			  where, ret, SSL_state_string_long(ssl),
			  net_ip2addr(&proxy->ip));
	}
}

static int ssl_verify_client_cert(int preverify_ok, X509_STORE_CTX *ctx)
{
	SSL *ssl;
        struct ssl_proxy *proxy;

	ssl = X509_STORE_CTX_get_ex_data(ctx,
					 SSL_get_ex_data_X509_STORE_CTX_idx());
	proxy = SSL_get_ex_data(ssl, extdata_index);
	proxy->cert_received = TRUE;

	if (proxy->set->verbose_ssl ||
	    (proxy->set->verbose_auth && !preverify_ok)) {
		char buf[1024];
		X509_NAME *subject;

		subject = X509_get_subject_name(ctx->current_cert);
		(void)X509_NAME_oneline(subject, buf, sizeof(buf));
		buf[sizeof(buf)-1] = '\0'; /* just in case.. */
		if (!preverify_ok)
			i_info("Invalid certificate: %s: %s", X509_verify_cert_error_string(ctx->error),buf);
		else
			i_info("Valid certificate: %s", buf);
	}
	if (!preverify_ok)
		proxy->cert_broken = TRUE;

	/* Return success anyway, because if ssl_require_client_cert=no we
	   could still allow authentication. */
	return 1;
}

static int
pem_password_callback(char *buf, int size, int rwflag ATTR_UNUSED,
		      void *userdata)
{
	if (userdata == NULL) {
		i_error("SSL private key file is password protected, "
			"but password isn't given");
		return 0;
	}

	if (i_strocpy(buf, userdata, size) < 0)
		return 0;
	return strlen(buf);
}

unsigned int ssl_proxy_get_count(void)
{
	return ssl_proxy_count;
}

static bool is_pem_key(const char *cert)
{
	return strstr(cert, "PRIVATE KEY---") != NULL;
}

static STACK_OF(X509_NAME) *load_ca(X509_STORE *store, const char *ca)
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
	if (inf == NULL)
		i_fatal("Couldn't parse ssl_ca: %s", ssl_last_error());
	BIO_free(bio);

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
	return xnames;
}

static STACK_OF(X509_NAME) *
ssl_proxy_ctx_init(SSL_CTX *ssl_ctx, const struct login_settings *set)
{
	X509_STORE *store;
	STACK_OF(X509_NAME) *xnames = NULL;

	SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL);
	if (*set->ssl_ca != '\0') {
		/* set trusted CA certs */
		store = SSL_CTX_get_cert_store(ssl_ctx);
		xnames = load_ca(store, set->ssl_ca);
	}
	SSL_CTX_set_info_callback(ssl_ctx, ssl_info_callback);
	if (SSL_CTX_need_tmp_RSA(ssl_ctx))
		SSL_CTX_set_tmp_rsa_callback(ssl_ctx, ssl_gen_rsa_key);
	SSL_CTX_set_tmp_dh_callback(ssl_ctx, ssl_tmp_dh_callback);
	return xnames;
}

static void
ssl_proxy_ctx_verify_client(SSL_CTX *ssl_ctx, STACK_OF(X509_NAME) *ca_names)
{
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
	X509_STORE *store;

	store = SSL_CTX_get_cert_store(ssl_ctx);
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
			     X509_V_FLAG_CRL_CHECK_ALL);
#endif
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
			   ssl_verify_client_cert);
	/* set list of CA names that are sent to client */
	SSL_CTX_set_client_CA_list(ssl_ctx, ca_names);
}

static const char *ssl_proxy_get_use_certificate_error(const char *cert)
{
	unsigned long err;

	err = ERR_peek_error();
	if (ERR_GET_LIB(err) != ERR_LIB_PEM ||
	    ERR_GET_REASON(err) != PEM_R_NO_START_LINE)
		return ssl_last_error();
	else if (is_pem_key(cert)) {
		return "The file contains a private key "
			"(you've mixed ssl_cert and ssl_key settings)";
	} else {
		return "There is no certificate.";
	}
}

static EVP_PKEY *ssl_proxy_load_key(const struct login_settings *set)
{
	EVP_PKEY *pkey;
	BIO *bio;
	const char *password;
	char *dup_password;

	bio = BIO_new_mem_buf(t_strdup_noconst(set->ssl_key),
			      strlen(set->ssl_key));
	if (bio == NULL)
		i_fatal("BIO_new_mem_buf() failed");

	password = *set->ssl_key_password != '\0' ? set->ssl_key_password :
		getenv(MASTER_SSL_KEY_PASSWORD_ENV);
	dup_password = t_strdup_noconst(password);
	pkey = PEM_read_bio_PrivateKey(bio, NULL, pem_password_callback,
				       dup_password);
	if (pkey == NULL)
		i_fatal("Couldn't parse private ssl_key");
	BIO_free(bio);
	return pkey;
}

static const char *ssl_key_load_error(void)
{
	unsigned long err = ERR_peek_error();

	if (ERR_GET_LIB(err) == ERR_LIB_X509 &&
	    ERR_GET_REASON(err) == X509_R_KEY_VALUES_MISMATCH)
		return "Key is for a different cert than ssl_cert";
	else
		return ssl_last_error();
}

static void ssl_proxy_ctx_use_key(SSL_CTX *ctx, const struct login_settings *set)
{
	EVP_PKEY *pkey;

	pkey = ssl_proxy_load_key(set);
	if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
		i_fatal("Can't load private ssl_key: %s", ssl_key_load_error());
	EVP_PKEY_free(pkey);
}

static int
ssl_proxy_ctx_use_certificate_chain(SSL_CTX *ctx, const char *cert)
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
#if 0
	/* This is in OpenSSL code, but it seems to cause failures.. */
	if (ERR_peek_error() != 0)
		ret = 0;
#endif

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

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
static void ssl_servername_callback(SSL *ssl, int *al ATTR_UNUSED,
				    void *context ATTR_UNUSED)
{
	struct ssl_server_context *ctx;
	struct ssl_proxy *proxy;
	struct client *client;
	const char *host;
	void **other_sets;

	proxy = SSL_get_ex_data(ssl, extdata_index);
	host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

	client = proxy->client;
	client->set = login_settings_read(master_service, client->pool,
					  &client->local_ip, &client->ip, host,
					  &other_sets);
	ctx = ssl_server_context_get(client->set);
	SSL_set_SSL_CTX(ssl, ctx->ctx);
}
#endif

static struct ssl_server_context *
ssl_server_context_init(const struct login_settings *set)
{
	struct ssl_server_context *ctx;
	SSL_CTX *ssl_ctx;
	pool_t pool;
	STACK_OF(X509_NAME) *xnames;

	pool = pool_alloconly_create("ssl server context", 2048);
	ctx = i_new(struct ssl_server_context, 1);
	ctx->pool = pool;
	ctx->cert = p_strdup(pool, set->ssl_cert);
	ctx->key = p_strdup(pool, set->ssl_key);
	ctx->ca = p_strdup(pool, set->ssl_ca);
	ctx->cipher_list = p_strdup(pool, set->ssl_cipher_list);
	ctx->verify_client_cert = set->ssl_verify_client_cert;

	ctx->ctx = ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (ssl_ctx == NULL)
		i_fatal("SSL_CTX_new() failed");
	xnames = ssl_proxy_ctx_init(ssl_ctx, set);

	if (SSL_CTX_set_cipher_list(ssl_ctx, ctx->cipher_list) != 1) {
		i_fatal("Can't set cipher list to '%s': %s",
			ctx->cipher_list, ssl_last_error());
	}

	if (ssl_proxy_ctx_use_certificate_chain(ctx->ctx, ctx->cert) != 1) {
		i_fatal("Can't load ssl_cert: %s",
			ssl_proxy_get_use_certificate_error(ctx->cert));
	}

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	if (SSL_CTX_set_tlsext_servername_callback(ctx->ctx,
						   ssl_servername_callback) != 1) {
		if (set->verbose_ssl)
			i_debug("OpenSSL library doesn't support SNI");
	}
#endif

	ssl_proxy_ctx_use_key(ctx->ctx, set);
	SSL_CTX_set_info_callback(ctx->ctx, ssl_info_callback);

	if (ctx->verify_client_cert)
		ssl_proxy_ctx_verify_client(ctx->ctx, xnames);

	hash_table_insert(ssl_servers, ctx, ctx);
	return ctx;
}

static void ssl_server_context_deinit(struct ssl_server_context **_ctx)
{
	struct ssl_server_context *ctx = *_ctx;

	SSL_CTX_free(ctx->ctx);
	pool_unref(&ctx->pool);
}

static void ssl_proxy_init_client(const struct login_settings *set)
{
	STACK_OF(X509_NAME) *xnames;

	if ((ssl_client_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
		i_fatal("SSL_CTX_new() failed");
	xnames = ssl_proxy_ctx_init(ssl_client_ctx, set);
	ssl_proxy_ctx_verify_client(ssl_client_ctx, xnames);
}

void ssl_proxy_init(void)
{
	const struct login_settings *set = global_login_settings;
	static char dovecot[] = "dovecot";
	unsigned char buf;

	if (strcmp(set->ssl, "no") == 0)
		return;

	SSL_library_init();
	SSL_load_error_strings();

	extdata_index = SSL_get_ex_new_index(0, dovecot, NULL, NULL, NULL);

	ssl_servers = hash_table_create(default_pool, default_pool, 0,
					ssl_server_context_hash,
					ssl_server_context_cmp);
	(void)ssl_server_context_init(set);

	ssl_proxy_init_client(set);
	ssl_username_nid = OBJ_txt2nid(set->ssl_cert_username_field);
	if (ssl_username_nid == NID_undef) {
		i_fatal("Invalid ssl_cert_username_field: %s",
			set->ssl_cert_username_field);
	}

	/* PRNG initialization might want to use /dev/urandom, make sure it
	   does it before chrooting. We might not have enough entropy at
	   the first try, so this function may fail. It's still been
	   initialized though. */
	(void)RAND_bytes(&buf, 1);

	memset(&ssl_params, 0, sizeof(ssl_params));
	ssl_params.path = SSL_PARAMETERS_PATH;

	ssl_proxy_count = 0;
        ssl_proxies = NULL;
	ssl_initialized = TRUE;
}

void ssl_proxy_deinit(void)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	if (!ssl_initialized)
		return;

	while (ssl_proxies != NULL)
		ssl_proxy_destroy(ssl_proxies);

	iter = hash_table_iterate_init(ssl_servers);
	while (hash_table_iterate(iter, &key, &value)) {
		struct ssl_server_context *ctx = value;

		ssl_server_context_deinit(&ctx);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&ssl_servers);

	ssl_free_parameters(&ssl_params);
	SSL_CTX_free(ssl_client_ctx);
	EVP_cleanup();
	ERR_free_strings();
}

#endif
