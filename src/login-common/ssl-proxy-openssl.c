/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "hash.h"
#include "ssl-proxy.h"

#ifdef HAVE_OPENSSL

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

enum ssl_io_action {
	SSL_ADD_INPUT,
	SSL_REMOVE_INPUT,
	SSL_ADD_OUTPUT,
	SSL_REMOVE_OUTPUT
};

struct ssl_proxy {
	int refcount;

	SSL *ssl;
	struct ip_addr ip;

	int fd_ssl, fd_plain;
	struct io *io_ssl_read, *io_ssl_write, *io_plain_read, *io_plain_write;

	unsigned char plainout_buf[1024];
	unsigned int plainout_size;

	unsigned char sslout_buf[1024];
	unsigned int sslout_size;

	unsigned int handshaked:1;
	unsigned int destroyed:1;
};

static SSL_CTX *ssl_ctx;
static struct hash_table *ssl_proxies;

static void plain_read(void *context);
static void plain_write(void *context);
static void ssl_write(struct ssl_proxy *proxy);
static void ssl_step(void *context);
static void ssl_proxy_destroy(struct ssl_proxy *proxy);
static int ssl_proxy_unref(struct ssl_proxy *proxy);

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
		if (proxy->io_ssl_read != NULL) {
			io_remove(proxy->io_ssl_read);
			proxy->io_ssl_read = NULL;
		}
		break;
	case SSL_ADD_OUTPUT:
		if (proxy->io_ssl_write != NULL)
			break;
		proxy->io_ssl_write = io_add(proxy->fd_ssl, IO_WRITE,
					     ssl_step, proxy);
		break;
	case SSL_REMOVE_OUTPUT:
		if (proxy->io_ssl_write != NULL) {
			io_remove(proxy->io_ssl_write);
			proxy->io_ssl_write = NULL;
		}
		break;
	}
}

static void plain_block_input(struct ssl_proxy *proxy, int block)
{
	if (block) {
		if (proxy->io_plain_read != NULL) {
			io_remove(proxy->io_plain_read);
			proxy->io_plain_read = NULL;
		}
	} else {
		if (proxy->io_plain_read == NULL) {
			proxy->io_plain_read = io_add(proxy->fd_plain, IO_READ,
						      plain_read, proxy);
		}
	}
}

static void plain_read(void *context)
{
	struct ssl_proxy *proxy = context;
	ssize_t ret;

	if (proxy->sslout_size == sizeof(proxy->sslout_buf)) {
		/* buffer full, block input until it's written */
		plain_block_input(proxy, TRUE);
		return;
	}

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
			ssl_write(proxy);
		}
	}
}

static void plain_write(void *context)
{
	struct ssl_proxy *proxy = context;
	ssize_t ret;

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
			if (proxy->io_plain_write != NULL) {
				io_remove(proxy->io_plain_write);
                                proxy->io_plain_write = NULL;
			}
		}

		ssl_set_io(proxy, SSL_ADD_INPUT);
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

static void ssl_handle_error(struct ssl_proxy *proxy, int ret, const char *func)
{
	const char *errstr;
	int err;

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
				  func, errstr, net_ip2host(&proxy->ip));
		}
		ssl_proxy_destroy(proxy);
		break;
	case SSL_ERROR_ZERO_RETURN:
		/* clean connection closing */
		ssl_proxy_destroy(proxy);
		break;
	case SSL_ERROR_SSL:
		if (verbose_ssl) {
			i_warning("%s failed: %s [%s]", func, ssl_last_error(),
				  net_ip2host(&proxy->ip));
		}
		ssl_proxy_destroy(proxy);
		break;
	default:
		i_warning("%s failed: unknown failure %d (%s) [%s]",
			  func, err, ssl_last_error(), net_ip2host(&proxy->ip));
		ssl_proxy_destroy(proxy);
		break;
	}
}

static void ssl_handshake(struct ssl_proxy *proxy)
{
	int ret;

	ret = SSL_accept(proxy->ssl);
	if (ret != 1)
		ssl_handle_error(proxy, ret, "SSL_accept()");
	else {
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
		proxy->sslout_size -= ret;
		memmove(proxy->sslout_buf, proxy->sslout_buf + ret,
			proxy->sslout_size);

		ssl_set_io(proxy, proxy->sslout_size > 0 ?
			   SSL_ADD_OUTPUT : SSL_REMOVE_OUTPUT);
		plain_block_input(proxy, FALSE);
	}
}

static void ssl_step(void *context)
{
	struct ssl_proxy *proxy = context;

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
		else
			ssl_write(proxy);
	}

	ssl_proxy_unref(proxy);
}

int ssl_proxy_new(int fd, struct ip_addr *ip)
{
	struct ssl_proxy *proxy;
	SSL *ssl;
	int sfd[2];

	if (!ssl_initialized)
		return -1;

	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		i_error("SSL_new() failed: %s", ssl_last_error());
		return -1;
	}

	SSL_set_accept_state(ssl);
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
	proxy->refcount = 1;
	proxy->ssl = ssl;
	proxy->fd_ssl = fd;
	proxy->fd_plain = sfd[0];
	proxy->ip = *ip;

	proxy->refcount++;
	ssl_handshake(proxy);
	if (!ssl_proxy_unref(proxy)) {
		/* handshake failed. return the disconnected socket anyway
		   so the caller doesn't try to use the old closed fd */
		return sfd[1];
	}

        main_ref();
	hash_insert(ssl_proxies, proxy, proxy);
	return sfd[1];
}

static int ssl_proxy_unref(struct ssl_proxy *proxy)
{
	if (--proxy->refcount > 0)
		return TRUE;

	hash_remove(ssl_proxies, proxy);

	(void)net_disconnect(proxy->fd_ssl);
	(void)net_disconnect(proxy->fd_plain);

	if (proxy->io_ssl_read != NULL)
		io_remove(proxy->io_ssl_read);
	if (proxy->io_ssl_write != NULL)
		io_remove(proxy->io_ssl_write);
	if (proxy->io_plain_read != NULL)
		io_remove(proxy->io_plain_read);
	if (proxy->io_plain_write != NULL)
		io_remove(proxy->io_plain_write);

	SSL_free(proxy->ssl);
	i_free(proxy);

	main_unref();
	return FALSE;
}

static void ssl_proxy_destroy(struct ssl_proxy *proxy)
{
	if (!proxy->destroyed) {
		proxy->destroyed = TRUE;
		ssl_proxy_unref(proxy);
	}
}

void ssl_proxy_init(void)
{
	const char *certfile, *keyfile, *paramfile;
	int ret;

	certfile = getenv("SSL_CERT_FILE");
	keyfile = getenv("SSL_KEY_FILE");
	paramfile = getenv("SSL_PARAM_FILE");

	if (certfile == NULL || keyfile == NULL || paramfile == NULL) {
		/* SSL support is disabled */
		return;
	}

	SSL_library_init();
	SSL_load_error_strings();

	if ((ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL)
		i_fatal("SSL_CTX_new() failed");

        ret = SSL_CTX_use_certificate_chain_file(ssl_ctx, certfile);
	if (ret != 1) {
		i_fatal("Can't load certificate file %s: %s",
			certfile, ssl_last_error());
	}

	ret = SSL_CTX_use_PrivateKey_file(ssl_ctx, keyfile, SSL_FILETYPE_PEM);
	if (ret != 1) {
		i_fatal("Can't load private key file %s: %s",
			keyfile, ssl_last_error());
	}

        ssl_proxies = hash_create(default_pool, default_pool, 0, NULL, NULL);
	ssl_initialized = TRUE;
}

static void ssl_proxy_destroy_hash(void *key __attr_unused__, void *value,
				   void *context __attr_unused__)
{
	ssl_proxy_unref(value);
}

void ssl_proxy_deinit(void)
{
	if (!ssl_initialized)
		return;

	hash_foreach(ssl_proxies, ssl_proxy_destroy_hash, NULL);
	hash_destroy(ssl_proxies);

	SSL_CTX_free(ssl_ctx);
}

#endif
