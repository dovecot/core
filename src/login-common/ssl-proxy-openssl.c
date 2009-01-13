/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "ostream.h"
#include "read-full.h"
#include "llist.h"
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

#define DOVECOT_SSL_DEFAULT_CIPHER_LIST "ALL:!LOW:!SSLv2"
/* Check every 30 minutes if parameters file has been updated */
#define SSL_PARAMFILE_CHECK_INTERVAL (60*30)

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
	struct ip_addr ip;

	int fd_ssl, fd_plain;
	struct io *io_ssl_read, *io_ssl_write, *io_plain_read, *io_plain_write;

	unsigned char plainout_buf[1024];
	unsigned int plainout_size;

	unsigned char sslout_buf[1024];
	unsigned int sslout_size;

	char *last_error;
	unsigned int handshaked:1;
	unsigned int destroyed:1;
	unsigned int cert_received:1;
	unsigned int cert_broken:1;
};

struct ssl_parameters {
	const char *fname;
	time_t last_mtime, last_check;
	int fd;

	DH *dh_512, *dh_1024;
};

static int extdata_index;
static SSL_CTX *ssl_ctx;
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

static void ssl_params_corrupted(const char *path)
{
	i_fatal("Corrupted SSL parameters file: %s/%s "
		"(delete it and also the one in %s)",
		getenv("LOGIN_DIR"), path, PKG_STATEDIR);
}

static void read_next(struct ssl_parameters *params, void *data, size_t size)
{
	int ret;

	if ((ret = read_full(params->fd, data, size)) < 0)
		i_fatal("read(%s) failed: %m", params->fname);
	if (ret == 0)
		ssl_params_corrupted(params->fname);
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
		ssl_params_corrupted(params->fname);

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
		ssl_params_corrupted(params->fname);
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
	struct stat st;
	ssize_t ret;
	char c;
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

	if (fstat(params->fd, &st) < 0)
		i_error("fstat(%s) failed: %m", params->fname);
	else
		params->last_mtime = st.st_mtime;

	ssl_free_parameters(params);
	while (read_dh_parameters_next(params)) ;

	if ((ret = read_full(params->fd, &c, 1)) < 0)
		i_fatal("read(%s) failed: %m", params->fname);
	else if (ret != 0) {
		/* more data than expected */
		ssl_params_corrupted(params->fname);
	}

	if (close(params->fd) < 0)
		i_error("close() failed: %m");
	params->fd = -1;
}

static void ssl_refresh_parameters(struct ssl_parameters *params)
{
	struct stat st;

	if (params->last_check > ioloop_time - SSL_PARAMFILE_CHECK_INTERVAL)
		return;
	params->last_check = ioloop_time;

	if (params->last_mtime == 0)
		ssl_read_parameters(params);
	else {
		if (stat(params->fname, &st) < 0)
			i_error("stat(%s) failed: %m", params->fname);
		else if (st.st_mtime != params->last_mtime)
			ssl_read_parameters(params);
	}
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

static const char *ssl_last_error(void)
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

	buf = t_malloc(err_size);
	buf[err_size-1] = '\0';
	ERR_error_string_n(err, buf, err_size-1);
	return buf;
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

	ret = SSL_accept(proxy->ssl);
	if (ret != 1)
		ssl_handle_error(proxy, ret, "SSL_accept()");
	else {
		i_free_and_null(proxy->last_error);
		proxy->handshaked = TRUE;

		ssl_set_io(proxy, SSL_ADD_INPUT);
		plain_block_input(proxy, FALSE);
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

int ssl_proxy_new(int fd, struct ip_addr *ip, struct ssl_proxy **proxy_r)
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
	proxy->fd_ssl = fd;
	proxy->fd_plain = sfd[0];
	proxy->ip = *ip;
        SSL_set_ex_data(ssl, extdata_index, proxy);

	ssl_proxy_count++;
	DLLIST_PREPEND(&ssl_proxies, proxy);

	ssl_step(proxy);
	main_ref();

	*proxy_r = proxy;
	return sfd[1];
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
	char buf[1024];
	const char *name;

	if (!ssl_proxy_has_valid_client_cert(proxy))
		return NULL;

	x509 = SSL_get_peer_certificate(proxy->ssl);
	if (x509 == NULL)
		return NULL; /* we should have had it.. */

	if (X509_NAME_get_text_by_NID(X509_get_subject_name(x509),
				      ssl_username_nid, buf, sizeof(buf)) < 0)
		name = "";
	else
		name = t_strndup(buf, sizeof(buf));
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
	int bits, alg_bits;

	if (!proxy->handshaked)
		return "";

	cipher = SSL_get_current_cipher(proxy->ssl);
	bits = SSL_CIPHER_get_bits(cipher, &alg_bits);
	return t_strdup_printf("%s with cipher %s (%d/%d bits)",
			       SSL_get_version(proxy->ssl),
			       SSL_CIPHER_get_name(cipher),
			       bits, alg_bits);
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

	main_listen_start();
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

static void *ssl_clean_malloc(size_t size)
{
	return p_malloc(system_clean_pool, size);
}

static void *ssl_clean_realloc(void *ptr, size_t size)
{
	return p_realloc(system_clean_pool, ptr, (size_t)-1, size);
}

static void ssl_clean_free(void *ptr)
{
	p_free(system_clean_pool, ptr);
}

static bool is_pem_key_file(const char *path)
{
	char buf[4096];
	int fd, ret;

	/* this code is used only for giving a better error message,
	   so it needs to catch only the normal key files */
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return FALSE;
	ret = read(fd, buf, sizeof(buf)-1);
	close(fd);
	if (ret <= 0)
		return FALSE;
	buf[ret] = '\0';
	return strstr(buf, "PRIVATE KEY---") != NULL;
}

void ssl_proxy_init(void)
{
	static char dovecot[] = "dovecot";
	const char *cafile, *certfile, *keyfile, *cipher_list, *username_field;
	char *password;
	unsigned char buf;
	unsigned long err;

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

	CRYPTO_set_mem_functions(ssl_clean_malloc, ssl_clean_realloc,
				 ssl_clean_free);
	SSL_library_init();
	SSL_load_error_strings();

	extdata_index = SSL_get_ex_new_index(0, dovecot, NULL, NULL, NULL);

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
		err = ERR_peek_error();
		if (ERR_GET_LIB(err) != ERR_LIB_PEM ||
		    ERR_GET_REASON(err) != PEM_R_NO_START_LINE) {
			i_fatal("Can't load certificate file %s: %s",
				certfile, ssl_last_error());
		} else if (is_pem_key_file(certfile)) {
			i_fatal("Can't load certificate file %s: "
				"The file contains a private key "
				"(you've mixed ssl_cert_file and ssl_key_file settings)",
				certfile);
		} else {
			i_fatal("Can't load certificate file %s: "
				"The file doesn't contain a certificate.",
				certfile);
		}
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
		SSL_CTX_set_client_CA_list(ssl_ctx,
					   SSL_load_client_CA_file(cafile));
	}

	username_field = getenv("SSL_CERT_USERNAME_FIELD");
	if (username_field == NULL)
		ssl_username_nid = NID_commonName;
	else {
		ssl_username_nid = OBJ_txt2nid(username_field);
		if (ssl_username_nid == NID_undef) {
			i_fatal("Invalid ssl_cert_username_field: %s",
				username_field);
		}
	}

	/* PRNG initialization might want to use /dev/urandom, make sure it
	   does it before chrooting. We might not have enough entropy at
	   the first try, so this function may fail. It's still been
	   initialized though. */
	(void)RAND_bytes(&buf, 1);

	ssl_proxy_count = 0;
        ssl_proxies = NULL;
	ssl_initialized = TRUE;
}

void ssl_proxy_deinit(void)
{
	if (!ssl_initialized)
		return;

	while (ssl_proxies != NULL)
		ssl_proxy_destroy(ssl_proxies);

	ssl_free_parameters(&ssl_params);
	SSL_CTX_free(ssl_ctx);
	EVP_cleanup();
	ERR_free_strings();
}

#endif
