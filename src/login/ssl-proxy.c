/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "ssl-proxy.h"

int ssl_initialized = FALSE;

#ifdef HAVE_SSL

#include <stdlib.h>
#include <gnutls/gnutls.h>

typedef struct {
	int refcount;

	GNUTLS_STATE state;
	int fd_ssl, fd_plain;
	IO io_ssl, io_plain;
	int io_ssl_dir;

	unsigned char outbuf_plain[1024];
	unsigned int outbuf_pos_plain;

	unsigned int send_left_ssl, send_left_plain;
} SSLProxy;

#define DH_BITS 1024

const int protocol_priority[] =
	{ GNUTLS_TLS1, GNUTLS_SSL3, 0 };
const int kx_priority[] =
	{ GNUTLS_KX_RSA, GNUTLS_KX_DHE_RSA, 0 };
const int cipher_priority[] =
	{ GNUTLS_CIPHER_RIJNDAEL_CBC, GNUTLS_CIPHER_3DES_CBC, 0 };
const int comp_priority[] =
	{ GNUTLS_COMP_ZLIB, GNUTLS_COMP_NULL, 0 };
const int mac_priority[] =
	{ GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };

static GNUTLS_CERTIFICATE_SERVER_CREDENTIALS x509_cred;
static GNUTLS_DH_PARAMS dh_params;

static void ssl_input(void *context, int handle, IO io);
static void plain_input(void *context, int handle, IO io);
static int ssl_proxy_destroy(SSLProxy *proxy);

static int proxy_recv_ssl(SSLProxy *proxy, void *data, unsigned int size)
{
	int rcvd;

	rcvd = gnutls_record_recv(proxy->state, data, size);
	if (rcvd > 0)
		return rcvd;

	if (rcvd == 0 || rcvd == GNUTLS_E_UNEXPECTED_PACKET_LENGTH) {
		/* disconnected, either by nicely telling us that we'll
		   close the connection, or by simply killing the
		   connection which gives us the packet length error. */
		ssl_proxy_destroy(proxy);
		return -1;
	}

	if (!gnutls_error_is_fatal(rcvd))
		return 0;

	/* fatal error occured */
	i_warning("Error reading from SSL client: %s", gnutls_strerror(rcvd));
	ssl_proxy_destroy(proxy);
	return -1;
}

static int proxy_send_ssl(SSLProxy *proxy, const void *data, unsigned int size)
{
	int sent;

	sent = gnutls_record_send(proxy->state, data, size);
	if (sent >= 0)
		return sent;

	if (!gnutls_error_is_fatal(sent))
		return 0;

	if (sent == GNUTLS_E_PUSH_ERROR) {
		/* disconnected */
		return -1;
	}

	/* error occured */
	i_warning("Error sending to SSL client: %s", gnutls_strerror(sent));
	ssl_proxy_destroy(proxy);
	return -1;
}

static int ssl_proxy_destroy(SSLProxy *proxy)
{
	if (--proxy->refcount > 0)
		return TRUE;

	gnutls_deinit(proxy->state);

	(void)net_disconnect(proxy->fd_ssl);
	(void)net_disconnect(proxy->fd_plain);

	if (proxy->io_ssl != NULL)
		io_remove(proxy->io_ssl);
	io_remove(proxy->io_plain);

	i_free(proxy);
	return FALSE;
}

static void ssl_output(void *context, int fd __attr_unused__,
		       IO io __attr_unused__)
{
        SSLProxy *proxy = context;
	int sent;

	sent = net_transmit(proxy->fd_plain,
			    proxy->outbuf_plain + proxy->outbuf_pos_plain,
			    proxy->send_left_plain);
	if (sent < 0) {
		/* disconnected */
		ssl_proxy_destroy(proxy);
		return;
	}

	proxy->send_left_plain -= sent;
	proxy->outbuf_pos_plain += sent;

	if (proxy->send_left_plain > 0)
		return;

	/* everything is sent, start reading again */
	io_remove(proxy->io_ssl);
	proxy->io_ssl = io_add(proxy->fd_ssl, IO_READ, ssl_input, proxy);
}

static void ssl_input(void *context, int fd __attr_unused__,
		      IO io __attr_unused__)
{
        SSLProxy *proxy = context;
	int rcvd, sent;

	rcvd = proxy_recv_ssl(proxy, proxy->outbuf_plain,
			      sizeof(proxy->outbuf_plain));
	if (rcvd <= 0)
		return;

	sent = net_transmit(proxy->fd_plain, proxy->outbuf_plain,
			    (unsigned int) rcvd);
	if (sent == rcvd)
		return;

	if (sent < 0) {
		/* disconnected */
		ssl_proxy_destroy(proxy);
		return;
	}

	/* everything wasn't sent - don't read anything until we've
	   sent it all */
        proxy->outbuf_pos_plain = 0;
	proxy->send_left_plain = rcvd - sent;

	io_remove(proxy->io_ssl);
	proxy->io_ssl = io_add(proxy->fd_ssl, IO_WRITE, ssl_output, proxy);
}

static void plain_output(void *context, int fd __attr_unused__,
			 IO io __attr_unused__)
{
	SSLProxy *proxy = context;
	int sent;

	/* FIXME: (void*) 1 is horrible kludge, but there's no need for us
	   to store the data as gnutls does it already, maybe it needes an
	   api change or some clarification how to do it better.. */
	sent = proxy_send_ssl(proxy, (void *) 1, proxy->send_left_ssl);
	if (sent <= 0)
		return;

	proxy->send_left_ssl -= sent;
	if (proxy->send_left_ssl > 0)
		return;

	/* everything is sent, start reading again */
	io_remove(proxy->io_plain);
	proxy->io_plain = io_add(proxy->fd_plain, IO_READ, plain_input, proxy);
}

static void plain_input(void *context, int fd __attr_unused__,
			IO io __attr_unused__)
{
	SSLProxy *proxy = context;
	char buf[1024];
	int rcvd, sent;

	rcvd = net_receive(proxy->fd_plain, buf, sizeof(buf));
	if (rcvd < 0) {
		/* disconnected */
		gnutls_bye(proxy->state, 1);
		ssl_proxy_destroy(proxy);
		return;
	}

	sent = proxy_send_ssl(proxy, buf, (unsigned int) rcvd);
	if (sent < 0 || sent == rcvd)
		return;

	/* everything wasn't sent - don't read anything until we've
	   sent it all */
	proxy->send_left_ssl = rcvd - sent;

	io_remove(proxy->io_plain);
	proxy->io_plain = io_add(proxy->fd_ssl, IO_WRITE, plain_output, proxy);
}

static GNUTLS_STATE initialize_state(void)
{
	GNUTLS_STATE state;

	gnutls_init(&state, GNUTLS_SERVER);

	gnutls_protocol_set_priority(state, protocol_priority);
	gnutls_cipher_set_priority(state, cipher_priority);
	gnutls_compression_set_priority(state, comp_priority);
	gnutls_kx_set_priority(state, kx_priority);
	gnutls_mac_set_priority(state, mac_priority);

	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, x509_cred);

	/*gnutls_certificate_server_set_request(state, GNUTLS_CERT_REQUEST);*/

	gnutls_dh_set_prime_bits(state, DH_BITS);
	return state;
}

static void ssl_handshake(void *context, int fd __attr_unused__,
			  IO io __attr_unused__)
{
	SSLProxy *proxy = context;
	int ret, dir;

        ret = gnutls_handshake(proxy->state);
	if (ret >= 0) {
		/* handshake done, now we can start reading */
		if (proxy->io_ssl != NULL)
			io_remove(proxy->io_ssl);

		proxy->io_plain = io_add(proxy->fd_plain, IO_READ,
					 plain_input, proxy);
		proxy->io_ssl = io_add(proxy->fd_ssl, IO_READ,
				       ssl_input, proxy);
		return;
	}

	if (gnutls_error_is_fatal(ret)) {
		ssl_proxy_destroy(proxy);
		return;
	}

	/* i/o interrupted */
	dir = gnutls_handshake_get_direction(proxy->state) == 0 ?
		IO_READ : IO_WRITE;
	if (proxy->io_ssl_dir != dir) {
		if (proxy->io_ssl != NULL)
			io_remove(proxy->io_ssl);
		proxy->io_ssl = io_add(proxy->fd_ssl, dir,
				       ssl_handshake, proxy);
		proxy->io_ssl_dir = dir;
	}
}

int ssl_proxy_new(int fd)
{
        SSLProxy *proxy;
	GNUTLS_STATE state;
	int sfd[2];

	if (!ssl_initialized)
		return -1;

	state = initialize_state();
	gnutls_transport_set_ptr(state, fd);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sfd) == -1) {
		i_error("socketpair() failed: %m");
		gnutls_deinit(state);
		return -1;
	}

	proxy = i_new(SSLProxy, 1);
	proxy->refcount = 1;
	proxy->state = state;
	proxy->fd_ssl = fd;
	proxy->fd_plain = sfd[0];

	proxy->refcount++;
	ssl_handshake(proxy, -1, NULL);
	if (!ssl_proxy_destroy(proxy))
		return -1;

	return sfd[1];
}

static void generate_dh_primes(void)
{
	gnutls_datum prime, generator;
	int ret;

	/* Generate Diffie Hellman parameters - for use with DHE
	   kx algorithms. These should be discarded and regenerated
	   once a day, once a week or once a month. Depends on the
	   security requirements. */
	if ((ret = gnutls_dh_params_init(&dh_params)) < 0) {
		i_fatal("gnutls_dh_params_init() failed: %s",
			gnutls_strerror(ret));
	}

	ret = gnutls_dh_params_generate(&prime, &generator, DH_BITS);
	if (ret < 0) {
		i_fatal("gnutls_dh_params_generate() failed: %s",
			gnutls_strerror(ret));
	}

	ret = gnutls_dh_params_set(dh_params, prime, generator, DH_BITS);
	if (ret < 0) {
		i_fatal("gnutls_dh_params_set() failed: %s",
			gnutls_strerror(ret));
	}

	free(prime.data);
	free(generator.data);
}

void ssl_proxy_init(void)
{
	const char *certfile, *keyfile;
	int ret;

	certfile = getenv("SSL_CERT_FILE");
	keyfile = getenv("SSL_KEY_FILE");

	if (certfile == NULL || keyfile == NULL) {
		/* SSL support is disabled */
		return;
	}

	if ((ret = gnutls_global_init() < 0)) {
		i_fatal("gnu_tls_global_init() failed: %s",
			gnutls_strerror(ret));
	}

	if ((ret = gnutls_certificate_allocate_cred(&x509_cred)) < 0) {
		i_fatal("gnutls_certificate_allocate_cred() failed: %s",
			gnutls_strerror(ret));
	}

	ret = gnutls_certificate_set_x509_key_file(x509_cred, certfile, keyfile,
						   GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		i_fatal("Can't load certificate files %s and %s: %s",
			certfile, keyfile, gnutls_strerror(ret));
	}

	generate_dh_primes();
	gnutls_certificate_set_dh_params(x509_cred, dh_params);

	ssl_initialized = TRUE;
}

void ssl_proxy_deinit(void)
{
	gnutls_certificate_free_cred(x509_cred);
	gnutls_global_deinit();
}

#else

/* no SSL support */

int ssl_proxy_new(int fd) { return -1; }
void ssl_proxy_init(void) {}
void ssl_proxy_deinit(void) {}

#endif
