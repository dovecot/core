/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "ostream.h"
#include "read-full.h"
#include "hash.h"
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

#define DOVECOT_SSL_DEFAULT_CIPHER_LIST "ALL:!LOW"
/* Check every 30 minutes if parameters file has been updated */
#define SSL_PARAMFILE_CHECK_INTERVAL (60*30)

#define PLAIN_OUTPUT_OPTIMAL_SIZE 2048

enum ssl_want {
	WANT_INPUT,
	WANT_OUTPUT
};

struct ssl_proxy {
	int refcount;

	SSL *ssl;
	struct ip_addr ip;

	int fd_ssl, fd_plain;
	struct io *io_ssl, *io_plain_input;

	enum ssl_want want;
	void (*step)(struct ssl_proxy *);
	unsigned int ssl_want_size;

	struct ostream *plain_output;

	unsigned char sslout_buf[1024];
	unsigned int sslout_size;

	unsigned int handshaked:1;
	unsigned int destroyed:1;
	unsigned int cert_received:1;
	unsigned int cert_broken:1;
};

struct ssl_parameters {
	const char *fname;
	time_t last_mtime;
	int fd;

	DH *dh_512, *dh_1024;
};

static int extdata_index;
static SSL_CTX *ssl_ctx;
static struct hash_table *ssl_proxies;
static struct ssl_parameters ssl_params;

static void ssl_input(struct ssl_proxy *proxy);
static void ssl_output(struct ssl_proxy *proxy);
static void ssl_step(void *context);
static void ssl_proxy_destroy(struct ssl_proxy *proxy);
static void ssl_proxy_unref(struct ssl_proxy *proxy);

static void read_next(struct ssl_parameters *params, void *data, size_t size)
{
	int ret;

	if ((ret = read_full(params->fd, data, size)) < 0)
		i_fatal("read(%s) failed: %m", params->fname);
	if (ret == 0)
		i_fatal("read(%s) failed: Unexpected EOF", params->fname);
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
		i_fatal("Corrupted SSL parameters file: %s", params->fname);

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

static void ssl_read_parameters(struct ssl_parameters *params)
{
	bool warned = FALSE;

	/* we'll wait until parameter file exists */
	for (;;) {
		params->fd = open(params->fname, O_RDONLY);
		if (params->fd != -1)
			break;

		if (errno != ENOENT) {
			i_fatal("Can't open SSL parameter file %s: %m",
				params->fname);
		}

		if (!warned) {
			i_warning("Waiting for SSL parameter file %s",
				  params->fname);
			warned = TRUE;
		}
		sleep(1);
	}

	ssl_free_parameters(params);
	while (read_dh_parameters_next(params)) ;

	if (close(params->fd) < 0)
		i_error("close() failed: %m");
	params->fd = -1;
}

static void ssl_refresh_parameters(struct ssl_parameters *params)
{
	struct stat st;

	if (params->last_mtime > ioloop_time - SSL_PARAMFILE_CHECK_INTERVAL)
		return;

	if (params->last_mtime == 0)
		ssl_read_parameters(params);
	else {
		if (stat(params->fname, &st) < 0)
			i_error("stat(%s) failed: %m", params->fname);
		else if (st.st_mtime != params->last_mtime)
			ssl_read_parameters(params);
	}
}

static const char *ssl_last_error(void)
{
	unsigned long err;
	char *buf;
	size_t err_size = 256;

	err = ERR_get_error();
	if (err == 0)
		return strerror(errno);

	buf = t_malloc(err_size);
	buf[err_size-1] = '\0';
	ERR_error_string_n(err, buf, err_size-1);
	return buf;
}

static void ssl_set_io(struct ssl_proxy *proxy, enum ssl_want want)
{
	if (proxy->io_ssl != NULL) {
		if (want == proxy->want)
			return;
		io_remove(&proxy->io_ssl);
	}

	proxy->want = want;
	switch (want) {
	case WANT_INPUT:
		proxy->io_ssl =
			io_add(proxy->fd_ssl, IO_READ, ssl_step, proxy);
		break;
	case WANT_OUTPUT:
		proxy->io_ssl =
			io_add(proxy->fd_ssl, IO_WRITE, ssl_step, proxy);
		break;
	}
}

static void
ssl_handle_error(struct ssl_proxy *proxy, int ret, const char *func_name,
		 void (*func)(struct ssl_proxy *), unsigned int want_size)
{
	const char *errstr;
	int err;

	err = SSL_get_error(proxy->ssl, ret);

	switch (err) {
	case SSL_ERROR_WANT_READ:
		proxy->step = func;
		proxy->ssl_want_size = want_size;
		ssl_set_io(proxy, WANT_INPUT);
		break;
	case SSL_ERROR_WANT_WRITE:
		proxy->step = func;
		proxy->ssl_want_size = want_size;
		ssl_set_io(proxy, WANT_OUTPUT);
		break;
	case SSL_ERROR_SYSCALL:
		/* eat up the error queue */
		if (verbose_ssl) {
			if (ERR_peek_error() != 0)
				errstr = ssl_last_error();
			else {
				if (ret == 0)
					errstr = "EOF";
				else
					errstr = strerror(errno);
			}

			i_warning("%s syscall failed: %s [%s]",
				  func_name, errstr, net_ip2addr(&proxy->ip));
		}
		ssl_proxy_destroy(proxy);
		break;
	case SSL_ERROR_ZERO_RETURN:
		/* clean connection closing */
		ssl_proxy_destroy(proxy);
		break;
	case SSL_ERROR_SSL:
		if (verbose_ssl) {
			i_warning("%s failed: %s [%s]", func_name,
				  ssl_last_error(), net_ip2addr(&proxy->ip));
		}
		ssl_proxy_destroy(proxy);
		break;
	default:
		i_warning("%s failed: unknown failure %d (%s) [%s]",
			  func_name, err, ssl_last_error(),
			  net_ip2addr(&proxy->ip));
		ssl_proxy_destroy(proxy);
		break;
	}
}

static void plain_input(void *context)
{
	struct ssl_proxy *proxy = context;
	ssize_t ret;

	if (proxy->sslout_size == sizeof(proxy->sslout_buf)) {
		/* buffer full, block input until it's written */
		io_remove(&proxy->io_plain_input);
		return;
	}

	ret = net_receive(proxy->fd_plain,
			  proxy->sslout_buf + proxy->sslout_size,
			  sizeof(proxy->sslout_buf) - proxy->sslout_size);
	if (ret <= 0) {
		if (ret < 0)
			ssl_proxy_destroy(proxy);
	} else {
		proxy->sslout_size += ret;
		if (SSL_want(proxy->ssl) == SSL_NOTHING) {
			i_assert(proxy->ssl_want_size == 0);
			ssl_output(proxy);
		}
	}
}

static int plain_output(void *context)
{
	struct ssl_proxy *proxy = context;
	int ret;

	if (proxy->ssl_want_size != 0)
		return 0;

	if ((ret = o_stream_flush(proxy->plain_output)) < 0) {
		ssl_proxy_destroy(proxy);
		return 1;
	}

	if (o_stream_get_buffer_used_size(proxy->plain_output) <
	    PLAIN_OUTPUT_OPTIMAL_SIZE &&
	    proxy->want == WANT_INPUT && proxy->io_ssl == NULL)
		ssl_set_io(proxy, WANT_INPUT);

	return ret;
}

static void ssl_handshake(struct ssl_proxy *proxy)
{
	int ret, old_errno;

	net_set_cork(proxy->fd_ssl, TRUE);
	ret = SSL_accept(proxy->ssl);

	old_errno = errno;
	net_set_cork(proxy->fd_ssl, FALSE);
	errno = old_errno;

	if (ret != 1)
		ssl_handle_error(proxy, ret, "SSL_accept()", ssl_handshake, 0);
	else {
		proxy->handshaked = TRUE;
		proxy->step = ssl_input;
		ssl_set_io(proxy, WANT_INPUT);

		proxy->io_plain_input = io_add(proxy->fd_plain, IO_READ,
					       plain_input, proxy);
	}
}

static void ssl_input(struct ssl_proxy *proxy)
{
	unsigned char buf[PLAIN_OUTPUT_OPTIMAL_SIZE];
	size_t size, used;
	ssize_t ret, ret2;

	used = o_stream_get_buffer_used_size(proxy->plain_output);
	if (used >= PLAIN_OUTPUT_OPTIMAL_SIZE) {
		io_remove(&proxy->io_ssl);
		return;
	}

	size = sizeof(buf) - used;
	if (proxy->ssl_want_size != 0) {
		i_assert(proxy->ssl_want_size <= size);
		size = proxy->ssl_want_size;
		proxy->ssl_want_size = 0;
	}

	ret = SSL_read(proxy->ssl, buf, size);
	if (ret <= 0) {
		ssl_handle_error(proxy, ret, "SSL_read()", ssl_input, size);
		return;
	}
	o_stream_cork(proxy->plain_output);
	ret2 = o_stream_send(proxy->plain_output, buf, ret);
	i_assert(ret2 < 0 || ret2 == ret);
	o_stream_uncork(proxy->plain_output);

	if (proxy->sslout_size > 0)
		ssl_output(proxy);
}

static void ssl_output(struct ssl_proxy *proxy)
{
	unsigned int size;
	int ret, old_errno;

	if (proxy->ssl_want_size == 0)
		size = proxy->sslout_size;
	else {
		i_assert(proxy->ssl_want_size <= proxy->sslout_size);
		size = proxy->ssl_want_size;
		proxy->ssl_want_size = 0;
	}

	net_set_cork(proxy->fd_ssl, TRUE);
	ret = SSL_write(proxy->ssl, proxy->sslout_buf, size);

	old_errno = errno;
	net_set_cork(proxy->fd_ssl, FALSE);
	errno = old_errno;

	if (ret <= 0) {
		ssl_handle_error(proxy, ret, "SSL_write()", ssl_output, size);
		return;
	}

	proxy->sslout_size -= ret;
	memmove(proxy->sslout_buf, proxy->sslout_buf + ret, proxy->sslout_size);

	if (proxy->sslout_size > 0) {
		ssl_set_io(proxy, WANT_OUTPUT);
		proxy->step = ssl_output;
	} else {
		ssl_set_io(proxy, WANT_INPUT);
		proxy->step = ssl_input;
	}
	if (proxy->io_plain_input == NULL) {
		proxy->io_plain_input = io_add(proxy->fd_plain, IO_READ,
					       plain_input, proxy);
	}
}

static void ssl_step(void *context)
{
	struct ssl_proxy *proxy = context;

	proxy->step(proxy);
}

int ssl_proxy_new(int fd, struct ip_addr *ip, struct ssl_proxy **proxy_r)
{
	struct ssl_proxy *proxy;
	SSL *ssl;
	int sfd[2];

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

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sfd) == -1) {
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
	proxy->fd_ssl = fd;
	proxy->fd_plain = sfd[0];
	proxy->ip = *ip;
	proxy->plain_output =
		o_stream_create_file(proxy->fd_plain, default_pool,
				     (size_t)-1, FALSE);
	o_stream_set_flush_callback(proxy->plain_output, plain_output, proxy);

        SSL_set_ex_data(ssl, extdata_index, proxy);

	hash_insert(ssl_proxies, proxy, proxy);

	proxy->step = ssl_handshake;
	ssl_handshake(proxy);
	main_ref();

	*proxy_r = proxy;
	return sfd[1];
}

bool ssl_proxy_has_valid_client_cert(struct ssl_proxy *proxy)
{
	return proxy->cert_received && !proxy->cert_broken;
}

const char *ssl_proxy_get_peer_name(struct ssl_proxy *proxy)
{
	X509 *x509;
	char buf[1024];
	const char *name;

	if (!ssl_proxy_has_valid_client_cert(proxy))
		return NULL;

	x509 = SSL_get_peer_certificate(proxy->ssl);
	if (x509 == NULL)
		return NULL; /* we should have had it.. */

	if (X509_NAME_get_text_by_NID(X509_get_subject_name(x509),
				      NID_commonName, buf, sizeof(buf)) < 0)
		name = "";
	else
		name = t_strndup(buf, sizeof(buf));
	X509_free(x509);
	
	return *name == '\0' ? NULL : name;
}

void ssl_proxy_free(struct ssl_proxy *proxy)
{
	ssl_proxy_unref(proxy);
}

static void ssl_proxy_unref(struct ssl_proxy *proxy)
{
	if (--proxy->refcount > 0)
		return;
	i_assert(proxy->refcount == 0);

	SSL_free(proxy->ssl);
	i_free(proxy);

	main_unref();
}

static void ssl_proxy_destroy(struct ssl_proxy *proxy)
{
	if (proxy->destroyed)
		return;
	proxy->destroyed = TRUE;

	hash_remove(ssl_proxies, proxy);

	if (proxy->io_ssl != NULL)
		io_remove(&proxy->io_ssl);
	if (proxy->io_plain_input != NULL)
		io_remove(&proxy->io_plain_input);

	o_stream_unref(&proxy->plain_output);
	(void)net_disconnect(proxy->fd_ssl);
	(void)net_disconnect(proxy->fd_plain);

	ssl_proxy_unref(proxy);
}

static RSA *ssl_gen_rsa_key(SSL *ssl __attr_unused__,
			    int is_export __attr_unused__, int keylength)
{
	return RSA_generate_key(keylength, RSA_F4, NULL, NULL);
}

static DH *ssl_tmp_dh_callback(SSL *ssl __attr_unused__,
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

	if (verbose_ssl || (verbose_auth && !preverify_ok)) {
		char buf[1024];
		X509_NAME *subject;

		subject = X509_get_subject_name(ctx->current_cert);
		(void)X509_NAME_oneline(subject, buf, sizeof(buf));
		buf[sizeof(buf)-1] = '\0'; /* just in case.. */
		if (!preverify_ok)
			i_info("Invalid certificate: %s", buf);
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
pem_password_callback(char *buf, int size, int rwflag __attr_unused__,
		      void *userdata)
{
	if (userdata == NULL) {
		i_error("SSL private key file is password protected, "
			"but password isn't given");
		return 0;
	}

	if (strocpy(buf, userdata, size) < 0)
		return 0;
	return strlen(buf);
}

void ssl_proxy_init(void)
{
	const char *cafile, *certfile, *keyfile, *cipher_list;
	char *password;
	unsigned char buf;

	memset(&ssl_params, 0, sizeof(ssl_params));

	cafile = getenv("SSL_CA_FILE");
	certfile = getenv("SSL_CERT_FILE");
	keyfile = getenv("SSL_KEY_FILE");
	ssl_params.fname = getenv("SSL_PARAM_FILE");
	password = getenv("SSL_KEY_PASSWORD");

	if (certfile == NULL || keyfile == NULL || ssl_params.fname == NULL) {
		/* SSL support is disabled */
		return;
	}

	SSL_library_init();
	SSL_load_error_strings();

	extdata_index = SSL_get_ex_new_index(0, "dovecot", NULL, NULL, NULL);

	if ((ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL)
		i_fatal("SSL_CTX_new() failed");

	SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL);

	cipher_list = getenv("SSL_CIPHER_LIST");
	if (cipher_list == NULL)
		cipher_list = DOVECOT_SSL_DEFAULT_CIPHER_LIST;
	if (SSL_CTX_set_cipher_list(ssl_ctx, cipher_list) != 1) {
		i_fatal("Can't set cipher list to '%s': %s",
			cipher_list, ssl_last_error());
	}

	if (cafile != NULL) {
		if (SSL_CTX_load_verify_locations(ssl_ctx, cafile, NULL) != 1) {
			i_fatal("Can't load CA file %s: %s",
				cafile, ssl_last_error());
		}
	}

	if (SSL_CTX_use_certificate_chain_file(ssl_ctx, certfile) != 1) {
		i_fatal("Can't load certificate file %s: %s",
			certfile, ssl_last_error());
	}

        SSL_CTX_set_default_passwd_cb(ssl_ctx, pem_password_callback);
        SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, password);
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, keyfile,
					SSL_FILETYPE_PEM) != 1) {
		i_fatal("Can't load private key file %s: %s",
			keyfile, ssl_last_error());
	}

	if (SSL_CTX_need_tmp_RSA(ssl_ctx))
		SSL_CTX_set_tmp_rsa_callback(ssl_ctx, ssl_gen_rsa_key);
	SSL_CTX_set_tmp_dh_callback(ssl_ctx, ssl_tmp_dh_callback);

	if (verbose_ssl)
		SSL_CTX_set_info_callback(ssl_ctx, ssl_info_callback);

	if (getenv("SSL_VERIFY_CLIENT_CERT") != NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
		X509_STORE *store;

		store = SSL_CTX_get_cert_store(ssl_ctx);
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
				     X509_V_FLAG_CRL_CHECK_ALL);
#endif
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER |
				   SSL_VERIFY_CLIENT_ONCE,
				   ssl_verify_client_cert);
	}

	/* PRNG initialization might want to use /dev/urandom, make sure it
	   does it before chrooting. We might not have enough entropy at
	   the first try, so this function may fail. It's still been
	   initialized though. */
	(void)RAND_bytes(&buf, 1);

        ssl_proxies = hash_create(default_pool, default_pool, 0, NULL, NULL);
	ssl_initialized = TRUE;
}

void ssl_proxy_deinit(void)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	if (!ssl_initialized)
		return;

	iter = hash_iterate_init(ssl_proxies);
	while (hash_iterate(iter, &key, &value))
		ssl_proxy_destroy(value);
	hash_iterate_deinit(iter);
	hash_destroy(ssl_proxies);

	ssl_free_parameters(&ssl_params);
	SSL_CTX_free(ssl_ctx);
}

#endif
