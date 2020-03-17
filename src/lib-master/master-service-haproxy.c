/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "ioloop.h"
#include "str-sanitize.h"
#include "master-service-private.h"
#include "master-service-settings.h"

#define HAPROXY_V1_MAX_HEADER_SIZE (108)

#define PP2_TYPE_ALPN           0x01
#define PP2_TYPE_AUTHORITY      0x02
#define PP2_TYPE_CRC32C         0x03
#define PP2_TYPE_NOOP           0x04
#define PP2_TYPE_SSL            0x20
#define PP2_SUBTYPE_SSL_VERSION 0x21
#define PP2_SUBTYPE_SSL_CN      0x22
#define PP2_SUBTYPE_SSL_CIPHER  0x23
#define PP2_SUBTYPE_SSL_SIG_ALG 0x24
#define PP2_SUBTYPE_SSL_KEY_ALG 0x25
#define PP2_TYPE_NETNS          0x30

#define PP2_CLIENT_SSL	   	0x01
#define PP2_CLIENT_CERT_CONN	0x02
#define PP2_CLIENT_CERT_SESS	0x04

enum haproxy_version_t {
	HAPROXY_VERSION_1,
	HAPROXY_VERSION_2,
};

enum {
	HAPROXY_CMD_LOCAL = 0x00,
	HAPROXY_CMD_PROXY = 0x01
};

enum {
	HAPROXY_AF_UNSPEC = 0x00,
	HAPROXY_AF_INET   = 0x01,
	HAPROXY_AF_INET6  = 0x02,
	HAPROXY_AF_UNIX   = 0x03
};

enum {
	HAPROXY_SOCK_UNSPEC = 0x00,
	HAPROXY_SOCK_STREAM = 0x01,
	HAPROXY_SOCK_DGRAM  = 0x02
};

static const char haproxy_v2sig[12] =
	"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

struct haproxy_header_v2 {
	uint8_t sig[12];
	uint8_t ver_cmd;
	uint8_t fam;
	uint16_t len;
};

struct haproxy_data_v2 {
	union {
		struct {  /* for TCP/UDP over IPv4, len = 12 */
			uint32_t src_addr;
			uint32_t dst_addr;
			uint16_t src_port;
			uint16_t dst_port;
		} ip4;
		struct {  /* for TCP/UDP over IPv6, len = 36 */
			uint8_t  src_addr[16];
			uint8_t  dst_addr[16];
			uint16_t src_port;
			uint16_t dst_port;
		} ip6;
		struct {  /* for AF_UNIX sockets, len = 216 */
			uint8_t src_addr[108];
			uint8_t dst_addr[108];
		} unx;
	} addr;
};

#define SIZEOF_PP2_TLV (1U+2U)
struct haproxy_pp2_tlv {
	uint8_t type;
	uint16_t len;
	const unsigned char *data;
};

#define SIZEOF_PP2_TLV_SSL (1U+4U)
struct haproxy_pp2_tlv_ssl {
	uint8_t client;
	uint32_t verify;

	size_t len;
	const unsigned char *data;
};

struct master_service_haproxy_conn {
	struct master_service_connection conn;

	pool_t pool;

	struct master_service_haproxy_conn *prev, *next;
	
	struct master_service *service;

	struct io *io;
	struct timeout *to;
};

static void
master_service_haproxy_conn_free(struct master_service_haproxy_conn *hpconn)
{
	struct master_service *service = hpconn->service;

	DLLIST_REMOVE(&service->haproxy_conns, hpconn);

	io_remove(&hpconn->io);
	timeout_remove(&hpconn->to);
	pool_unref(&hpconn->pool);
}

static void
master_service_haproxy_conn_failure(struct master_service_haproxy_conn *hpconn)
{
	struct master_service *service = hpconn->service;
	struct master_service_connection conn = hpconn->conn;

	master_service_haproxy_conn_free(hpconn);
	master_service_client_connection_handled(service, &conn);
}

static void
master_service_haproxy_conn_success(struct master_service_haproxy_conn *hpconn)
{
	struct master_service *service = hpconn->service;
	struct master_service_connection conn = hpconn->conn;

	master_service_haproxy_conn_free(hpconn);
	master_service_client_connection_callback(service, &conn);
}

static void
master_service_haproxy_timeout(struct master_service_haproxy_conn *hpconn)
{
	i_error("haproxy: Client timed out (rip=%s)",
		net_ip2addr(&hpconn->conn.remote_ip));
	master_service_haproxy_conn_failure(hpconn);
}

static int
master_service_haproxy_recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t ret;

	do {
		ret = recv(fd, buf, len, flags);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0 && errno == EAGAIN)
		return 0;
	if (ret <= 0) {
		if (ret == 0)
			errno = ECONNRESET;
		return -1;
	}

	return ret;
}

static int get_ssl_tlv(const unsigned char *kvdata, size_t dlen,
		       struct haproxy_pp2_tlv_ssl *kv)
{
	if (dlen < SIZEOF_PP2_TLV_SSL)
		return -1;
	kv->client = kvdata[0];
	/* spec does not specify the endianess of this field */
	kv->verify = cpu32_to_cpu_unaligned(kvdata+1);
	kv->data = kvdata+SIZEOF_PP2_TLV_SSL;
	kv->len = dlen - SIZEOF_PP2_TLV_SSL;
	return 0;
}

static int get_tlv(const unsigned char *kvdata, size_t dlen,
		   struct haproxy_pp2_tlv *kv)
{
	if (dlen < SIZEOF_PP2_TLV)
		return -1;

	/* spec says
		uint8_t type
		uint8_t len_hi
		uint8_t len_lo
	  so we combine the hi and lo here. */
	kv->type = kvdata[0];
	kv->len = (kvdata[1]<<8)+kvdata[2];
	kv->data = kvdata + SIZEOF_PP2_TLV;

	if (kv->len + SIZEOF_PP2_TLV > dlen)
		return -1;

	return 0;
}

static int
master_service_haproxy_parse_ssl_tlv(struct master_service_haproxy_conn *hpconn,
				     const struct haproxy_pp2_tlv_ssl *ssl_kv,
				     const char **error_r)
{
	hpconn->conn.proxy.ssl = (ssl_kv->client & (PP2_CLIENT_SSL)) != 0;

	/* try parse some more */
	for(size_t i = 0; i < ssl_kv->len;) {
		struct haproxy_pp2_tlv kv;
		if (get_tlv(ssl_kv->data + i, ssl_kv->len - i, &kv) < 0) {
			*error_r = t_strdup_printf("get_tlv(%zu) failed: "
						   "Truncated data", i);
			return -1;
		}
		i += SIZEOF_PP2_TLV + kv.len;
		switch(kv.type) {
		/* we don't care about these */
		case PP2_SUBTYPE_SSL_CIPHER:
		case PP2_SUBTYPE_SSL_SIG_ALG:
		case PP2_SUBTYPE_SSL_KEY_ALG:
			break;
		case PP2_SUBTYPE_SSL_CN:
			hpconn->conn.proxy.cert_common_name =
				p_strndup(hpconn->pool, kv.data, kv.len);
			break;
		}
	}
	return 0;
}

static int
master_service_haproxy_parse_tlv(struct master_service_haproxy_conn *hpconn,
				 const unsigned char *buf, size_t blen,
				 const char **error_r)
{
	for(size_t i = 0; i < blen;) {
		struct haproxy_pp2_tlv kv;
                struct haproxy_pp2_tlv_ssl ssl_kv;

		if (get_tlv(buf + i, blen - i, &kv) < 0) {
			*error_r = t_strdup_printf("get_tlv(%zu) failed: "
						   "Truncated data", i);
			return -1;
		}

                /* skip unsupported values */
                switch(kv.type) {
		case PP2_TYPE_ALPN:
			hpconn->conn.proxy.alpn_size = kv.len;
			hpconn->conn.proxy.alpn =
				p_memdup(hpconn->pool, kv.data, kv.len);
			break;
                case PP2_TYPE_AUTHORITY:
                        /* store hostname somewhere */
                        hpconn->conn.proxy.hostname =
				p_strndup(hpconn->pool, kv.data, kv.len);
                        break;
                case PP2_TYPE_SSL:
			if (get_ssl_tlv(kv.data, kv.len, &ssl_kv) < 0) {
				*error_r = t_strdup_printf("get_ssl_tlv(%zu) failed: "
							   "Truncated data", i);
				return -1;
			}
                        if (master_service_haproxy_parse_ssl_tlv(hpconn, &ssl_kv, error_r)<0)
				return -1;
                        break;
		}
		i += SIZEOF_PP2_TLV + kv.len;
        }
	return 0;
}

static int
master_service_haproxy_read(struct master_service_haproxy_conn *hpconn)
{
	/* reasonable max size for haproxy data */
	unsigned char rbuf[1500];
	const char *error;
	static union {
		unsigned char v1_data[HAPROXY_V1_MAX_HEADER_SIZE];
		struct {
			const struct haproxy_header_v2 hdr;
			const struct haproxy_data_v2 data;
		} v2;
	} buf;
	struct ip_addr *real_remote_ip = &hpconn->conn.remote_ip;
	int fd = hpconn->conn.fd;
	struct ip_addr local_ip, remote_ip;
	in_port_t local_port, remote_port;
	size_t size,i,want;
	ssize_t ret;
	enum haproxy_version_t version;

	/* the protocol specification explicitly states that the protocol header
	   must be sent as one TCP frame, meaning that we will get it in full
	   with the first recv() call.
	 */
	i_zero(&buf);
	i_zero(&rbuf);

	/* see if there is a HAPROXY protocol command waiting */
	if ((ret = master_service_haproxy_recv(fd, &buf, sizeof(buf), MSG_PEEK))<=0) {
		if (ret < 0)
			i_info("haproxy: Client disconnected (rip=%s): %m",
			       net_ip2addr(real_remote_ip));
		return ret;
	/* see if there is a haproxy command, 8 is used later on as well */
	} else if (ret >= 8 && memcmp(buf.v1_data, "PROXY", 5) == 0) {
		/* fine */
		version = HAPROXY_VERSION_1;
	} else if ((size_t)ret >= sizeof(buf.v2.hdr) &&
		   memcmp(buf.v2.hdr.sig, haproxy_v2sig, sizeof(haproxy_v2sig)) == 0) {
		want = ntohs(buf.v2.hdr.len) + sizeof(buf.v2.hdr);
		if (want > sizeof(rbuf)) {
			i_error("haproxy: Client disconnected: Too long header (rip=%s)",
				net_ip2addr(real_remote_ip));
			return -1;
		}

		if ((ret = master_service_haproxy_recv(fd, rbuf, want, MSG_WAITALL))<=0) {
			if (ret < 0)
				i_info("haproxy: Client disconnected (rip=%s): %m",
				       net_ip2addr(real_remote_ip));
			return ret;
		}

		if (ret != (ssize_t)want) {
			i_info("haproxy: Client disconnected: Failed to read full header (rip=%s)",
				net_ip2addr(real_remote_ip));
			return -1;
		}
		memcpy(&buf, rbuf, sizeof(buf));
		version = HAPROXY_VERSION_2;
	} else {
		/* it wasn't haproxy data */
		i_error("haproxy: Client disconnected: "
			"Failed to read valid HAproxy data (rip=%s)",
			net_ip2addr(real_remote_ip));
		return -1;
	}

	/* don't update true connection data until we succeed */
	local_ip = hpconn->conn.local_ip;
	remote_ip = hpconn->conn.remote_ip;
	local_port = hpconn->conn.local_port;
	remote_port = hpconn->conn.remote_port;

	/* protocol version 2 */
	if (version == HAPROXY_VERSION_2) {
		const struct haproxy_header_v2 *hdr = &buf.v2.hdr;
		const struct haproxy_data_v2 *data = &buf.v2.data;
		size_t hdr_len;

		i_assert(ret >= (ssize_t)sizeof(buf.v2.hdr));

		if ((hdr->ver_cmd & 0xf0) != 0x20) {
			i_error("haproxy: Client disconnected: "
				"Unsupported protocol version (version=%02x, rip=%s)",
				(hdr->ver_cmd & 0xf0) >> 4,
				net_ip2addr(real_remote_ip));
			return -1;
		}

		hdr_len = ntohs(hdr->len);
		size = sizeof(*hdr) + hdr_len;
		/* keep tab of how much address data there really is because
		   because TLVs begin after that. */
		i = 0;

		if (ret < (ssize_t)size) {
			i_error("haproxy(v2): Client disconnected: "
				"Protocol payload length does not match header "
				"(got=%zu, expect=%zu, rip=%s)",
				(size_t)ret, size, net_ip2addr(real_remote_ip));
			return -1;
		}

		i += sizeof(*hdr);

		switch (hdr->ver_cmd & 0x0f) {
		case HAPROXY_CMD_LOCAL:
			/* keep local connection address for LOCAL */
			/*i_debug("haproxy(v2): Local connection (rip=%s)",
				net_ip2addr(real_remote_ip));*/
			break;
		case HAPROXY_CMD_PROXY:
			if ((hdr->fam & 0x0f) != HAPROXY_SOCK_STREAM) {
				/* UDP makes no sense currently */
				i_error("haproxy(v2): Client disconnected: "
					"Not using TCP (type=%02x, rip=%s)",
					(hdr->fam & 0x0f), net_ip2addr(real_remote_ip));
				return -1;
			}
			switch ((hdr->fam & 0xf0) >> 4) {
			case HAPROXY_AF_INET:
				/* IPv4 */
				if (hdr_len < sizeof(data->addr.ip4)) {
					i_error("haproxy(v2): Client disconnected: "
						"IPv4 data is incomplete (rip=%s)",
						net_ip2addr(real_remote_ip));
					return -1;
				}
				local_ip.family = AF_INET;
				local_ip.u.ip4.s_addr = data->addr.ip4.dst_addr;
				local_port = ntohs(data->addr.ip4.dst_port);
				remote_ip.family = AF_INET;
				remote_ip.u.ip4.s_addr = data->addr.ip4.src_addr;
				remote_port = ntohs(data->addr.ip4.src_port);
				i += sizeof(data->addr.ip4);
				break;
			case HAPROXY_AF_INET6:
				/* IPv6 */
				if (hdr_len < sizeof(data->addr.ip6)) {
					i_error("haproxy(v2): Client disconnected: "
						"IPv6 data is incomplete (rip=%s)",
						net_ip2addr(real_remote_ip));
					return -1;
				}
				local_ip.family = AF_INET6;
				memcpy(&local_ip.u.ip6.s6_addr, data->addr.ip6.dst_addr, 16);
				local_port = ntohs(data->addr.ip6.dst_port);
				remote_ip.family = AF_INET6;
				memcpy(&remote_ip.u.ip6.s6_addr, data->addr.ip6.src_addr, 16);
				remote_port = ntohs(data->addr.ip6.src_port);
				i += sizeof(data->addr.ip6);
				break;
			case HAPROXY_AF_UNSPEC:
			case HAPROXY_AF_UNIX:
				/* unsupported; ignored */
				i_error("haproxy(v2): Unsupported address family "
					"(family=%02x, rip=%s)", (hdr->fam & 0xf0) >> 4,
					net_ip2addr(real_remote_ip));
				break;
			default:
				/* unsupported; error */
				i_error("haproxy(v2): Client disconnected: "
					"Unknown address family "
					"(family=%02x, rip=%s)", (hdr->fam & 0xf0) >> 4,
					net_ip2addr(real_remote_ip));
				return -1;
			}
			break;
		default:
			i_error("haproxy(v2): Client disconnected: "
				"Invalid command (cmd=%02x, rip=%s)",
				(hdr->ver_cmd & 0x0f),
				net_ip2addr(real_remote_ip));
			return -1; /* not a supported command */
		}

		if (master_service_haproxy_parse_tlv(hpconn, rbuf+i, size-i, &error) < 0) {
			i_error("haproxy(v2): Client disconnected: "
				"Invalid TLV: %s (cmd=%02x, rip=%s)",
				error,
				(hdr->ver_cmd & 0x0f),
				net_ip2addr(real_remote_ip));
			return -1;
		}
	/* protocol version 1 (soon obsolete) */
	} else if (version == HAPROXY_VERSION_1) {
		unsigned char *data = buf.v1_data, *end;
		const char *const *fields;
		unsigned int family = 0;

		i_assert(ret >= 8);

		/* find end of header line */
		end = memchr(data, '\r', ret - 1);
		if (end == NULL || end[1] != '\n')
			return -1;
		*end = '\0';
		size = end + 2 - data;

		/* magic */
		fields = t_strsplit((char *)data, " ");
		i_assert(strcmp(*fields, "PROXY") == 0);
		fields++;

		/* protocol */
		if (*fields == NULL) {
			i_error("haproxy(v1): Client disconnected: "
				"Field for proxied protocol is missing "
				"(rip=%s)", net_ip2addr(real_remote_ip));
			return -1;
		}
		if (strcmp(*fields, "TCP4") == 0) {
			family = AF_INET;
		} else if (strcmp(*fields, "TCP6") == 0) {
			family = AF_INET6;
		} else if (strcmp(*fields, "UNKNOWN") == 0) {
			family = 0;
		} else {
			i_error("haproxy(v1): Client disconnected: "
				"Unknown proxied protocol "
				"(protocol=`%s', rip=%s)", str_sanitize(*fields, 64),
				net_ip2addr(real_remote_ip));
			return -1;
		}
		fields++;

		if (family != 0) {
			/* remote address */
			if (*fields == NULL) {
				i_error("haproxy(v1): Client disconnected: "
					"Field for proxied remote address is missing "
					"(rip=%s)", net_ip2addr(real_remote_ip));
				return -1;
			}
			if (net_addr2ip(*fields, &remote_ip) < 0 ||
				remote_ip.family != family) {
				i_error("haproxy(v1): Client disconnected: "
					"Proxied remote address is invalid "
					"(address=`%s', rip=%s)", str_sanitize(*fields, 64),
					net_ip2addr(real_remote_ip));
				return -1;
			}
			fields++;

			/* local address */
			if (*fields == NULL) {
				i_error("haproxy(v1): Client disconnected: "
					"Field for proxied local address is missing "
					"(rip=%s)", net_ip2addr(real_remote_ip));
				return -1;
			}
			if (net_addr2ip(*fields, &local_ip) < 0 ||
				local_ip.family != family) {
				i_error("haproxy(v1): Client disconnected: "
					"Proxied local address is invalid "
					"(address=`%s', rip=%s)", str_sanitize(*fields, 64),
					net_ip2addr(real_remote_ip));
				return -1;
			}
			fields++;

			/* remote port */
			if (*fields == NULL) {
				i_error("haproxy(v1): Client disconnected: "
					"Field for proxied local port is missing "
					"(rip=%s)", net_ip2addr(real_remote_ip));
				return -1;
			}
			if (net_str2port(*fields, &remote_port) < 0) {
				i_error("haproxy(v1): Client disconnected: "
					"Proxied remote port is invalid "
					"(port=`%s', rip=%s)", str_sanitize(*fields, 64),
					net_ip2addr(real_remote_ip));
				return -1;
			}
			fields++;

			/* local port */
			if (*fields == NULL) {
				i_error("haproxy(v1): Client disconnected: "
					"Field for proxied local port is missing "
					"(rip=%s)", net_ip2addr(real_remote_ip));
				return -1;
			}
			if (net_str2port(*fields, &local_port) < 0) {
				i_error("haproxy(v1): Client disconnected: "
					"Proxied local port is invalid "
					"(port=`%s', rip=%s)", str_sanitize(*fields, 64),
					net_ip2addr(real_remote_ip));
				return -1;
			}
			fields++;

			if (*fields != NULL) {
				i_error("haproxy(v1): Client disconnected: "
					"Header line has spurius extra field "
					"(field=`%s', rip=%s)", str_sanitize(*fields, 64),
					net_ip2addr(real_remote_ip));
				return -1;
			}
		}
		i_assert(size <= sizeof(buf));

		if ((ret = master_service_haproxy_recv(fd, &buf, size, 0))<=0) {
			if (ret < 0)
				i_info("haproxy: Client disconnected (rip=%s): %m",
				       net_ip2addr(real_remote_ip));
			return ret;
		} else if (ret != (ssize_t)size) {
			i_error("haproxy: Client disconnected: "
				"Failed to read full header (rip=%s)",
				net_ip2addr(real_remote_ip));
			return -1;
		}
	/* invalid protocol */
	} else {
		i_unreached();
	}

	/* assign data from proxy */
	hpconn->conn.local_ip = local_ip;
	hpconn->conn.remote_ip = remote_ip;
	hpconn->conn.local_port = local_port;
	hpconn->conn.remote_port = remote_port;
	hpconn->conn.proxied = TRUE;

	return 1;
}

static void
master_service_haproxy_input(struct master_service_haproxy_conn *hpconn)
{
	int ret;

	if ((ret = master_service_haproxy_read(hpconn)) <= 0) {
		if (ret < 0)
			master_service_haproxy_conn_failure(hpconn);
	} else {
		master_service_haproxy_conn_success(hpconn);
	}
}

static bool
master_service_haproxy_conn_is_trusted(struct master_service *service,
				       struct master_service_connection *conn)
{
	const char *const *net;
	struct ip_addr net_ip;
	unsigned int bits;

	if (service->set->haproxy_trusted_networks == NULL)
		return FALSE;

	net = t_strsplit_spaces(service->set->haproxy_trusted_networks, ", ");
	for (; *net != NULL; net++) {
		if (net_parse_range(*net, &net_ip, &bits) < 0) {
			i_error("haproxy_trusted_networks: "
				"Invalid network '%s'", *net);
			break;
		}

		if (net_is_in_network(&conn->real_remote_ip, &net_ip, bits))
			return TRUE;
	}
	return FALSE;
}

void master_service_haproxy_new(struct master_service *service,
				struct master_service_connection *conn)
{
	struct master_service_haproxy_conn *hpconn;
	pool_t pool;

	if (!master_service_haproxy_conn_is_trusted(service, conn)) {
		i_warning("haproxy: Client not trusted (rip=%s)",
			  net_ip2addr(&conn->real_remote_ip));
		master_service_client_connection_handled(service, conn);
		return;
	}

	pool = pool_alloconly_create("haproxy connection", 128);
	hpconn = p_new(pool, struct master_service_haproxy_conn, 1);
	hpconn->pool = pool;
	hpconn->conn = *conn;
	hpconn->service = service;
	DLLIST_PREPEND(&service->haproxy_conns, hpconn);

	hpconn->io = io_add(conn->fd, IO_READ,
			    master_service_haproxy_input, hpconn);
	hpconn->to = timeout_add(service->set->haproxy_timeout*1000,
				 master_service_haproxy_timeout, hpconn);
}

void master_service_haproxy_abort(struct master_service *service)
{
	while (service->haproxy_conns != NULL) {
		int fd = service->haproxy_conns->conn.fd;

		master_service_haproxy_conn_free(service->haproxy_conns);
		i_close_fd(&fd);
	}
}

