/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "ssl-proxy.h"

#ifdef HAVE_OPENSSL

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef enum {
	SSL_STATE_HANDSHAKE,
	SSL_STATE_READ,
	SSL_STATE_WRITE
} SSLState;

typedef struct {
	int refcount;

	SSL *ssl;
        SSLState state;

	int fd_ssl, fd_plain;
	IO io_ssl, io_plain_read, io_plain_write;
	int io_ssl_dir;

	unsigned char plainout_buf[1024];
	unsigned int plainout_pos, plainout_size;

	unsigned char sslout_buf[1024];
	unsigned int sslout_pos, sslout_size;
} SSLProxy;

static SSL_CTX *ssl_ctx;

static void plain_read(SSLProxy *proxy);
static void plain_write(SSLProxy *proxy);

static int ssl_proxy_destroy(SSLProxy *proxy);
static void ssl_set_direction(SSLProxy *proxy, int dir);

static void plain_block_input(SSLProxy *proxy, int block)
{
	if (block) {
		if (proxy->io_plain_read != NULL) {
			io_remove(proxy->io_plain_read);
			proxy->io_plain_read = NULL;
		}
	} else {
		if (proxy->io_plain_read == NULL) {
			proxy->io_plain_read =
				io_add(proxy->fd_plain, IO_READ,
				       (IOFunc) plain_read, proxy);
		}
	}
}

static void ssl_block(SSLProxy *proxy, int block)
{
	i_assert(proxy->state == SSL_STATE_READ);

	if (block) {
		if (proxy->io_ssl != NULL) {
			io_remove(proxy->io_ssl);
			proxy->io_ssl = NULL;
		}

		proxy->io_ssl_dir = -2;
	} else {
		proxy->io_ssl_dir = -1;
		ssl_set_direction(proxy, IO_READ);
	}
}

static void plain_read(SSLProxy *proxy)
{
	ssize_t ret;

	i_assert(proxy->sslout_size == 0);

	ret = net_receive(proxy->fd_plain, proxy->sslout_buf,
			  sizeof(proxy->sslout_buf));
	if (ret < 0)
		ssl_proxy_destroy(proxy);
	else if (ret > 0) {
		proxy->sslout_size = ret;
		proxy->sslout_pos = 0;

		proxy->state = SSL_STATE_WRITE;
		ssl_set_direction(proxy, IO_WRITE);

		plain_block_input(proxy, TRUE);
	}
}

static void plain_write(SSLProxy *proxy)
{
	ssize_t ret;

	ret = net_transmit(proxy->fd_plain,
			   proxy->plainout_buf + proxy->plainout_pos,
			   proxy->plainout_size);
	if (ret < 0)
		ssl_proxy_destroy(proxy);
	else {
		proxy->plainout_size -= ret;
		proxy->plainout_pos += ret;

		if (proxy->plainout_size > 0) {
			ssl_block(proxy, TRUE);
			if (proxy->io_plain_write == NULL) {
				proxy->io_plain_write =
					io_add(proxy->fd_plain, IO_WRITE,
					       (IOFunc) plain_write, proxy);
			}
		} else {
			proxy->plainout_pos = 0;
			ssl_block(proxy, FALSE);

			if (proxy->io_plain_write != NULL) {
				io_remove(proxy->io_plain_write);
                                proxy->io_plain_write = NULL;
			}
		}
	}

}

const char *ssl_last_error(void)
{
	unsigned long err;
	char *buf;

	err = ERR_get_error();
	if (err == 0)
		return strerror(errno);

	buf = t_malloc(256);
	buf[255] = '\0';
	ERR_error_string_n(err, buf, 255);
	return buf;
}

static void ssl_handle_error(SSLProxy *proxy, int err, const char *func)
{
	err = SSL_get_error(proxy->ssl, err);

	switch (err) {
	case SSL_ERROR_WANT_READ:
		ssl_set_direction(proxy, IO_READ);
		break;
	case SSL_ERROR_WANT_WRITE:
		ssl_set_direction(proxy, IO_WRITE);
		break;
	case SSL_ERROR_SYSCALL:
		/* eat up the error queue */
		if (err != 0)
			i_warning("%s failed: %s", func, ssl_last_error());
		ssl_proxy_destroy(proxy);
		break;
	case SSL_ERROR_ZERO_RETURN:
		/* clean connection closing */
		ssl_proxy_destroy(proxy);
		break;
	case SSL_ERROR_SSL:
		i_warning("%s failed: %s", func, ssl_last_error());
		ssl_proxy_destroy(proxy);
		break;
	default:
		i_warning("%s failed: unknown failure %d (%s)",
			  func, err, ssl_last_error());
		ssl_proxy_destroy(proxy);
		break;
	}
}

static void ssl_handshake_step(SSLProxy *proxy)
{
	int ret;

	ret = SSL_accept(proxy->ssl);
	if (ret != 1) {
		plain_block_input(proxy, TRUE);
		ssl_handle_error(proxy, ret, "SSL_accept()");
	} else {
		plain_block_input(proxy, FALSE);
		ssl_set_direction(proxy, IO_READ);
		proxy->state = SSL_STATE_READ;
	}
}

static void ssl_read_step(SSLProxy *proxy)
{
	int ret;

	i_assert(proxy->plainout_size == 0);

	ret = SSL_read(proxy->ssl, proxy->plainout_buf,
		       sizeof(proxy->plainout_buf));
	if (ret <= 0) {
		plain_block_input(proxy, TRUE);
		ssl_handle_error(proxy, ret, "SSL_read()");
	} else {
		plain_block_input(proxy, FALSE);
		ssl_set_direction(proxy, IO_READ);

		proxy->plainout_pos = 0;
		proxy->plainout_size = ret;
		plain_write(proxy);
	}
}

static void ssl_write_step(SSLProxy *proxy)
{
	int ret;

	ret = SSL_write(proxy->ssl, proxy->sslout_buf + proxy->sslout_pos,
			proxy->sslout_size);
	if (ret <= 0) {
		plain_block_input(proxy, TRUE);
		ssl_handle_error(proxy, ret, "SSL_write()");
	} else {
		proxy->sslout_size -= ret;
		proxy->sslout_pos += ret;

		if (proxy->sslout_size > 0) {
			plain_block_input(proxy, TRUE);
			ssl_set_direction(proxy, IO_WRITE);
			proxy->state = SSL_STATE_WRITE;
		} else {
			plain_block_input(proxy, FALSE);
			ssl_set_direction(proxy, IO_READ);
			proxy->state = SSL_STATE_READ;
			proxy->sslout_pos = 0;
		}
	}
}

static void ssl_step(void *context, int fd __attr_unused__,
		     IO io __attr_unused__)
{
        SSLProxy *proxy = context;

	switch (proxy->state) {
	case SSL_STATE_HANDSHAKE:
		ssl_handshake_step(proxy);
		break;
	case SSL_STATE_READ:
		ssl_read_step(proxy);
		break;
	case SSL_STATE_WRITE:
		ssl_write_step(proxy);
		break;
	}
}

static void ssl_set_direction(SSLProxy *proxy, int dir)
{
	i_assert(proxy->io_ssl_dir != -2);

	if (proxy->io_ssl_dir == dir)
		return;

	if (proxy->io_ssl != NULL)
		io_remove(proxy->io_ssl);
	proxy->io_ssl = io_add(proxy->fd_ssl, dir, ssl_step, proxy);
}

int ssl_proxy_new(int fd)
{
	SSLProxy *proxy;
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
		return -1;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sfd) == -1) {
		i_error("socketpair() failed: %m");
		SSL_free(ssl);
		return -1;
	}

	net_set_nonblock(sfd[0], TRUE);
	net_set_nonblock(sfd[1], TRUE);

	proxy = i_new(SSLProxy, 1);
	proxy->refcount = 1;
	proxy->ssl = ssl;
	proxy->fd_ssl = fd;
	proxy->fd_plain = sfd[0];

	proxy->state = SSL_STATE_HANDSHAKE;
	ssl_set_direction(proxy, IO_READ);

	proxy->refcount++;
	ssl_handshake_step(proxy);
	if (!ssl_proxy_destroy(proxy))
		return -1;

        main_ref();
	return sfd[1];
}

static int ssl_proxy_destroy(SSLProxy *proxy)
{
	if (--proxy->refcount > 0)
		return TRUE;

	SSL_free(proxy->ssl);

	(void)net_disconnect(proxy->fd_ssl);
	(void)net_disconnect(proxy->fd_plain);

	if (proxy->io_ssl != NULL)
		io_remove(proxy->io_ssl);
	if (proxy->io_plain_read != NULL)
		io_remove(proxy->io_plain_read);
	if (proxy->io_plain_write != NULL)
		io_remove(proxy->io_plain_write);

	i_free(proxy);

	main_unref();
	return FALSE;
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

	ssl_initialized = TRUE;
}

void ssl_proxy_deinit(void)
{
	if (ssl_initialized)
                SSL_CTX_free(ssl_ctx);
}

#endif
