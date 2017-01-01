/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "ioloop.h"
#include "str-sanitize.h"
#include "master-service-private.h"
#include "master-service-settings.h"

#define HAPROXY_V1_MAX_HEADER_SIZE (108)

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

struct master_service_haproxy_conn {
	struct master_service_connection conn;

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

	if (hpconn->io != NULL)
		io_remove(&hpconn->io);
	if (hpconn->to != NULL)
		timeout_remove(&hpconn->to);
	i_free(hpconn);
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
master_service_haproxy_read(struct master_service_haproxy_conn *hpconn)
{
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
	size_t size;
	ssize_t ret;

	/* the protocol specification explicitly states that the protocol header
	   must be sent as one TCP frame, meaning that we will get it in full
	   with the first recv() call.
	   FIXME: still, it would be cleaner to allow reading it incrementally.
	 */
	do {
		ret = recv(fd, &buf, sizeof(buf), MSG_PEEK);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0 && errno == EAGAIN)
		return 0;
	if (ret <= 0) {
		i_info("haproxy: Client disconnected (rip=%s)",
		       net_ip2addr(real_remote_ip));
		return -1;
	}

	/* don't update true connection data until we succeed */
	local_ip = hpconn->conn.local_ip;
	remote_ip = hpconn->conn.remote_ip;
	local_port = hpconn->conn.local_port;
	remote_port = hpconn->conn.remote_port;

	/* protocol version 2 */
	if (ret >= (ssize_t)sizeof(buf.v2.hdr) &&
	    memcmp(buf.v2.hdr.sig, haproxy_v2sig,
		   sizeof(buf.v2.hdr.sig)) == 0) {
		const struct haproxy_header_v2 *hdr = &buf.v2.hdr;
		const struct haproxy_data_v2 *data = &buf.v2.data;
		size_t hdr_len;

		if ((hdr->ver_cmd & 0xf0) != 0x20) {
			i_error("haproxy: Client disconnected: "
				"Unsupported protocol version (version=%02x, rip=%s)",
				(hdr->ver_cmd & 0xf0) >> 4,
				net_ip2addr(real_remote_ip));
			return -1;
		}

		hdr_len = ntohs(hdr->len);
		size = sizeof(*hdr) + hdr_len;
		if (ret < (ssize_t)size) {
			i_error("haproxy(v2): Client disconnected: "
				"Protocol payload length does not match header "
				"(got=%"PRIuSIZE_T", expect=%"PRIuSIZE_T", rip=%s)",
				(size_t)ret, size, net_ip2addr(real_remote_ip));
			return -1;
		}

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

		// FIXME: TLV vectors are ignored
		//         (useful to see whether proxied client is using SSL)

	/* protocol version 1 (soon obsolete) */
	} else if (ret >= 8 && memcmp(buf.v1_data, "PROXY", 5) == 0) {
		unsigned char *data = buf.v1_data, *end;
		const char *const *fields;
		unsigned int family = 0;

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

	/* invalid protocol */
	} else {
		i_error("haproxy: Client disconnected: "
			"No valid proxy header found (rip=%s)",
			net_ip2addr(real_remote_ip));
		return -1;
	}

	/* remove proxy protocol header from socket buffer */
	i_assert(size <= sizeof(buf));
	do {
		  ret = recv(fd, &buf, size, 0);
	} while (ret == -1 && errno == EINTR);

	if (ret <= 0) {
		i_info("haproxy: Client disconnected (rip=%s)",
		       net_ip2addr(real_remote_ip));
		return -1;
	}
	if (ret != (ssize_t)size) {
		/* not supposed to happen */
		i_error("haproxy: Client disconencted: "
			"Failed to read full header (rip=%s)",
			net_ip2addr(real_remote_ip));
		return -1;
	}

	/* assign data from proxy */
	hpconn->conn.local_ip = local_ip;
	hpconn->conn.remote_ip = remote_ip;
	hpconn->conn.local_port = local_port;
	hpconn->conn.remote_port = remote_port;
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

	if (!master_service_haproxy_conn_is_trusted(service, conn)) {
		i_warning("haproxy: Client not trusted (rip=%s)",
			  net_ip2addr(&conn->real_remote_ip));
		master_service_client_connection_handled(service, conn);
		return;
	}

	hpconn = i_new(struct master_service_haproxy_conn, 1);
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

