/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "ioloop.h"
#include "network.h"
#include "hash.h"
#include "ssl-proxy.h"

#ifdef HAVE_GNUTLS

#error broken currently

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <gnutls/gnutls.h>

struct ssl_proxy {
	int refcount;

	gnutls_session session;
	struct ip_addr ip;

	int fd_ssl, fd_plain;
	struct io *io_ssl, *io_plain;
	int io_ssl_dir;

	unsigned char outbuf_plain[1024];
	unsigned int outbuf_pos_plain;

	size_t send_left_ssl, send_left_plain;
};

const int protocol_priority[] =
	{ GNUTLS_TLS1, GNUTLS_SSL3, 0 };
const int kx_priority[] =
	{ GNUTLS_KX_DHE_DSS, GNUTLS_KX_RSA, GNUTLS_KX_DHE_RSA, 0 };
const int cipher_priority[] =
	{ GNUTLS_CIPHER_RIJNDAEL_CBC, GNUTLS_CIPHER_3DES_CBC,
	  GNUTLS_CIPHER_ARCFOUR_128, GNUTLS_CIPHER_ARCFOUR_40, 0 };
const int comp_priority[] =
	{ GNUTLS_COMP_LZO, GNUTLS_COMP_ZLIB, GNUTLS_COMP_NULL, 0 };
const int mac_priority[] =
	{ GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };
const int cert_type_priority[] =
	{ GNUTLS_CRT_X509, 0 };

static struct hash_table *ssl_proxies;
static gnutls_certificate_credentials x509_cred;
static gnutls_dh_params dh_params;
static gnutls_rsa_params rsa_params;

static void ssl_input(struct ssl_proxy *proxy);
static void plain_input(struct ssl_proxy *proxy);
static bool ssl_proxy_destroy(struct ssl_proxy *proxy);

static const char *get_alert_text(struct ssl_proxy *proxy)
{
	return gnutls_alert_get_name(gnutls_alert_get(proxy->session));
}

static int handle_ssl_error(struct ssl_proxy *proxy, int error)
{
	if (!gnutls_error_is_fatal(error)) {
		if (!verbose_ssl)
			return 0;

		if (error == GNUTLS_E_WARNING_ALERT_RECEIVED) {
			i_warning("Received SSL warning alert: %s [%s]",
				  get_alert_text(proxy),
				  net_ip2addr(&proxy->ip));
		} else {
			i_warning("Non-fatal SSL error: %s: %s",
				  get_alert_text(proxy),
				  net_ip2addr(&proxy->ip));
		}
		return 0;
	}

	if (verbose_ssl) {
		/* fatal error occurred */
		if (error == GNUTLS_E_FATAL_ALERT_RECEIVED) {
			i_warning("Received SSL fatal alert: %s [%s]",
				  get_alert_text(proxy),
				  net_ip2addr(&proxy->ip));
		} else {
			i_warning("Error reading from SSL client: %s [%s]",
				  gnutls_strerror(error),
				  net_ip2addr(&proxy->ip));
		}
	}

        gnutls_alert_send_appropriate(proxy->session, error);
	ssl_proxy_destroy(proxy);
	return -1;
}

static int proxy_recv_ssl(struct ssl_proxy *proxy, void *data, size_t size)
{
	int rcvd;

	rcvd = gnutls_record_recv(proxy->session, data, size);
	if (rcvd > 0)
		return rcvd;

	if (rcvd == 0 || rcvd == GNUTLS_E_UNEXPECTED_PACKET_LENGTH) {
		/* disconnected, either by nicely telling us that we'll
		   close the connection, or by simply killing the
		   connection which gives us the packet length error. */
		ssl_proxy_destroy(proxy);
		return -1;
	}

	return handle_ssl_error(proxy, rcvd);
}

static int proxy_send_ssl(struct ssl_proxy *proxy,
			  const void *data, size_t size)
{
	int sent;

	sent = gnutls_record_send(proxy->session, data, size);
	if (sent >= 0)
		return sent;

	if (sent == GNUTLS_E_PUSH_ERROR || sent == GNUTLS_E_INVALID_SESSION) {
		/* don't warn about errors related to unexpected
		   disconnection */
		ssl_proxy_destroy(proxy);
		return -1;
	}

	return handle_ssl_error(proxy, sent);
}

static int ssl_proxy_destroy(struct ssl_proxy *proxy)
{
	if (--proxy->refcount > 0)
		return TRUE;

	hash_table_remove(ssl_proxies, proxy);

	gnutls_deinit(proxy->session);

	if (proxy->io_ssl != NULL)
		io_remove(proxy->io_ssl);
	if (proxy->io_plain != NULL)
		io_remove(proxy->io_plain);

	(void)net_disconnect(proxy->fd_ssl);
	(void)net_disconnect(proxy->fd_plain);

	i_free(proxy);

	main_unref();
	return FALSE;
}

static void ssl_output(struct ssl_proxy *proxy)
{
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

static void ssl_input(struct ssl_proxy *proxy)
{
	int rcvd, sent;

	rcvd = proxy_recv_ssl(proxy, proxy->outbuf_plain,
			      sizeof(proxy->outbuf_plain));
	if (rcvd <= 0)
		return;

	sent = net_transmit(proxy->fd_plain, proxy->outbuf_plain, (size_t)rcvd);
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

static void plain_output(struct ssl_proxy *proxy)
{
	int sent;

	sent = proxy_send_ssl(proxy, NULL, proxy->send_left_ssl);
	if (sent <= 0)
		return;

	proxy->send_left_ssl -= sent;
	if (proxy->send_left_ssl > 0)
		return;

	/* everything is sent, start reading again */
	io_remove(proxy->io_plain);
	proxy->io_plain = io_add(proxy->fd_plain, IO_READ, plain_input, proxy);
}

static void plain_input(struct ssl_proxy *proxy)
{
	char buf[1024];
	ssize_t rcvd, sent;

	rcvd = net_receive(proxy->fd_plain, buf, sizeof(buf));
	if (rcvd < 0) {
		/* disconnected */
		gnutls_bye(proxy->session, 1);
		ssl_proxy_destroy(proxy);
		return;
	}

	sent = proxy_send_ssl(proxy, buf, (size_t)rcvd);
	if (sent < 0 || sent == rcvd)
		return;

	/* everything wasn't sent - don't read anything until we've
	   sent it all */
	proxy->send_left_ssl = rcvd - sent;

	io_remove(proxy->io_plain);
	proxy->io_plain = io_add(proxy->fd_ssl, IO_WRITE, plain_output, proxy);
}

static void ssl_handshake(struct ssl_proxy *proxy)
{
	int ret, dir;

        ret = gnutls_handshake(proxy->session);
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

	if (handle_ssl_error(proxy, ret) < 0)
		return;

	/* i/o interrupted */
	dir = gnutls_record_get_direction(proxy->session) == 0 ?
		IO_READ : IO_WRITE;
	if (proxy->io_ssl_dir != dir) {
		if (proxy->io_ssl != NULL)
			io_remove(proxy->io_ssl);
		proxy->io_ssl = io_add(proxy->fd_ssl, dir,
				       ssl_handshake, proxy);
		proxy->io_ssl_dir = dir;
	}
}

static gnutls_session initialize_state(void)
{
	gnutls_session session;

	gnutls_init(&session, GNUTLS_SERVER);

	gnutls_protocol_set_priority(session, protocol_priority);
	gnutls_cipher_set_priority(session, cipher_priority);
	gnutls_compression_set_priority(session, comp_priority);
	gnutls_kx_set_priority(session, kx_priority);
	gnutls_mac_set_priority(session, mac_priority);
	gnutls_certificate_type_set_priority(session, cert_type_priority);

	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
	return session;
}

int ssl_proxy_new(int fd, struct ip_addr *ip)
{
        struct ssl_proxy *proxy;
	gnutls_session session;
	int sfd[2];

	if (!ssl_initialized) {
		i_error("SSL support not enabled in configuration");
		return -1;
	}

	session = initialize_state();
	gnutls_transport_set_ptr(session, fd);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sfd) == -1) {
		i_error("socketpair() failed: %m");
		gnutls_deinit(session);
		return -1;
	}

	net_set_nonblock(sfd[0], TRUE);
	net_set_nonblock(sfd[1], TRUE);
	net_set_nonblock(fd, TRUE);

	proxy = i_new(struct ssl_proxy, 1);
	proxy->refcount = 1;
	proxy->session = session;
	proxy->fd_ssl = fd;
	proxy->fd_plain = sfd[0];
	proxy->ip = *ip;

	hash_table_insert(ssl_proxies, proxy, proxy);

	proxy->refcount++;
	ssl_handshake(proxy);
	if (!ssl_proxy_destroy(proxy)) {
		/* handshake failed. return the disconnected socket anyway
		   so the caller doesn't try to use the old closed fd */
		return sfd[1];
	}

        main_ref();
	return sfd[1];
}

static void read_next_field(int fd, gnutls_datum *datum,
			    const char *fname, const char *field_name)
{
        ssize_t ret;

	/* get size */
	ret = read(fd, &datum->size, sizeof(datum->size));
	if (ret < 0)
		i_fatal("read() failed for %s: %m", fname);

	if (ret != sizeof(datum->size)) {
		(void)unlink(fname);
		i_fatal("Corrupted SSL parameter file %s: File too small",
			fname);
	}

	if (datum->size > 10240) {
		(void)unlink(fname);
		i_fatal("Corrupted SSL parameter file %s: "
			"Field '%s' too large (%u)",
			fname, field_name, datum->size);
	}

	/* read the actual data */
	datum->data = t_malloc(datum->size);
	ret = read(fd, datum->data, datum->size);
	if (ret < 0)
		i_fatal("read() failed for %s: %m", fname);

	if ((size_t)ret != datum->size) {
		(void)unlink(fname);
		i_fatal("Corrupted SSL parameter file %s: "
			"Field '%s' not fully in file (%u < %u)",
			fname, field_name, datum->size - ret, datum->size);
	}
}

static void read_dh_parameters(int fd, const char *fname)
{
	gnutls_datum dbits, prime, generator;
	int ret, bits;

	if ((ret = gnutls_dh_params_init(&dh_params)) < 0) {
		i_fatal("gnutls_dh_params_init() failed: %s",
			gnutls_strerror(ret));
	}

	/* read until bits field is 0 */
	for (;;) {
		read_next_field(fd, &dbits, fname, "DH bits");

		if (dbits.size != sizeof(int)) {
			(void)unlink(fname);
			i_fatal("Corrupted SSL parameter file %s: "
				"Field 'DH bits' has invalid size %u",
				fname, dbits.size);
		}

		bits = *((int *) dbits.data);
		if (bits == 0)
			break;

		read_next_field(fd, &prime, fname, "DH prime");
		read_next_field(fd, &generator, fname, "DH generator");

		ret = gnutls_dh_params_set(dh_params, prime, generator, bits);
		if (ret < 0) {
			i_fatal("gnutls_dh_params_set() failed: %s",
				gnutls_strerror(ret));
		}
	}
}

static void read_rsa_parameters(int fd, const char *fname)
{
	gnutls_datum m, e, d, p, q, u;
	int ret;

	read_next_field(fd, &m, fname, "RSA m");
	read_next_field(fd, &e, fname, "RSA e");
	read_next_field(fd, &d, fname, "RSA d");
	read_next_field(fd, &p, fname, "RSA p");
	read_next_field(fd, &q, fname, "RSA q");
	read_next_field(fd, &u, fname, "RSA u");

	if ((ret = gnutls_rsa_params_init(&rsa_params)) < 0) {
		i_fatal("gnutls_rsa_params_init() failed: %s",
			gnutls_strerror(ret));
	}

	/* only 512bit is allowed */
	ret = gnutls_rsa_params_set(rsa_params, m, e, d, p, q, u, 512);
	if (ret < 0) {
		i_fatal("gnutls_rsa_params_set() failed: %s",
			gnutls_strerror(ret));
	}
}

static void read_parameters(const char *fname)
{
	int fd;

	/* we'll wait until parameter file exists */
	for (;;) {
		fd = open(fname, O_RDONLY);
		if (fd != -1)
			break;

		if (errno != ENOENT)
			i_fatal("Can't open SSL parameter file %s: %m", fname);

		sleep(1);
	}

	read_dh_parameters(fd, fname);
	read_rsa_parameters(fd, fname);

	(void)close(fd);
}

static void gcrypt_log_handler(void *context ATTR_UNUSED, int level,
			       const char *fmt, va_list args)
{
	if (level != GCRY_LOG_FATAL)
		return;

	T_BEGIN {
		i_error("gcrypt fatal: %s", t_strdup_vprintf(fmt, args));
	} T_END;
}

void ssl_proxy_init(void)
{
	const char *certfile, *keyfile, *paramfile;
	unsigned char buf[4];
	int ret;

	certfile = getenv("SSL_CERT_FILE");
	keyfile = getenv("SSL_KEY_FILE");
	paramfile = getenv("SSL_PARAM_FILE");

	if (certfile == NULL || keyfile == NULL || paramfile == NULL) {
		/* SSL support is disabled */
		return;
	}

	if ((ret = gnutls_global_init() < 0)) {
		i_fatal("gnu_tls_global_init() failed: %s",
			gnutls_strerror(ret));
	}

	/* gcrypt initialization - set log handler and make sure randomizer
	   opens /dev/urandom now instead of after we've chrooted */
	gcry_set_log_handler(gcrypt_log_handler, NULL);
	gcry_randomize(buf, sizeof(buf), GCRY_STRONG_RANDOM);

	read_parameters(paramfile);

	if ((ret = gnutls_certificate_allocate_credentials(&x509_cred)) < 0) {
		i_fatal("gnutls_certificate_allocate_credentials() failed: %s",
			gnutls_strerror(ret));
	}

	ret = gnutls_certificate_set_x509_key_file(x509_cred, certfile, keyfile,
						   GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		i_fatal("Can't load certificate files %s and %s: %s",
			certfile, keyfile, gnutls_strerror(ret));
	}

        gnutls_certificate_set_dh_params(x509_cred, dh_params);
        gnutls_certificate_set_rsa_export_params(x509_cred, rsa_params);

	ssl_proxies = hash_table_create(system_pool, system_pool, 0,
					NULL, NULL);
	ssl_initialized = TRUE;
}

void ssl_proxy_deinit(void)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	if (!ssl_initialized)
		return;

	iter = hash_table_iterate_init(ssl_proxies);
	while (hash_table_iterate(iter, &key, &value))
		ssl_proxy_destroy(value);
	hash_table_iterate_deinit(iter);
	hash_table_destroy(ssl_proxies);

	gnutls_certificate_free_credentials(x509_cred);
	gnutls_global_deinit();
}

#endif
