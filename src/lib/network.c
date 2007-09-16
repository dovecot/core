/* Copyright (c) 1999-2005 Timo Sirainen */

#include "lib.h"
#include "close-keep-errno.h"
#include "fd-set-nonblock.h"
#include "network.h"

#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/un.h>
#include <netinet/tcp.h>

union sockaddr_union {
	struct sockaddr sa;
	struct sockaddr_in sin;
#ifdef HAVE_IPV6
	struct sockaddr_in6 sin6;
#endif
};

#ifdef HAVE_IPV6
#  define SIZEOF_SOCKADDR(so) ((so).sa.sa_family == AF_INET6 ? \
	sizeof(so.sin6) : sizeof(so.sin))
#else
#  define SIZEOF_SOCKADDR(so) (sizeof(so.sin))
#endif

bool net_ip_compare(const struct ip_addr *ip1, const struct ip_addr *ip2)
{
	if (ip1->family != ip2->family)
		return 0;

#ifdef HAVE_IPV6
	if (ip1->family == AF_INET6) {
		return memcmp(&ip1->u.ip6, &ip2->u.ip6,
			      sizeof(ip1->u.ip6)) == 0;
	}
#endif

	return memcmp(&ip1->u.ip4, &ip2->u.ip4, sizeof(ip1->u.ip4)) == 0;
}

unsigned int net_ip_hash(const struct ip_addr *ip)
{
        const unsigned char *p;
	unsigned int len, g, h = 0;

#ifdef HAVE_IPV6
	if (ip->family == AF_INET6) {
		p = ip->u.ip6.s6_addr;
		len = sizeof(ip->u.ip6);
	} else
#endif
	{
		return ip->u.ip4.s_addr;
	}

	for (; len > 0; len--, p++) {
		h = (h << 4) + *p;
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
	}

	return h;
}

/* copy IP to sockaddr */
static inline void
sin_set_ip(union sockaddr_union *so, const struct ip_addr *ip)
{
	if (ip == NULL) {
#ifdef HAVE_IPV6
		so->sin6.sin6_family = AF_INET6;
		so->sin6.sin6_addr = in6addr_any;
#else
		so->sin.sin_family = AF_INET;
		so->sin.sin_addr.s_addr = INADDR_ANY;
#endif
		return;
	}

	so->sin.sin_family = ip->family;
#ifdef HAVE_IPV6
	if (ip->family == AF_INET6)
		memcpy(&so->sin6.sin6_addr, &ip->u.ip6, sizeof(ip->u.ip6));
	else
#endif
		memcpy(&so->sin.sin_addr, &ip->u.ip4, sizeof(ip->u.ip4));
}

static inline void
sin_get_ip(const union sockaddr_union *so, struct ip_addr *ip)
{
	ip->family = so->sin.sin_family;

#ifdef HAVE_IPV6
	if (ip->family == AF_INET6)
		memcpy(&ip->u.ip6, &so->sin6.sin6_addr, sizeof(ip->u.ip6));
	else
#endif
	if (ip->family == AF_INET)
		memcpy(&ip->u.ip4, &so->sin.sin_addr, sizeof(ip->u.ip4));
	else
		memset(&ip->u, 0, sizeof(ip->u));
}

static inline void sin_set_port(union sockaddr_union *so, unsigned int port)
{
#ifdef HAVE_IPV6
	if (so->sin.sin_family == AF_INET6)
                so->sin6.sin6_port = htons((unsigned short) port);
	else
#endif
		so->sin.sin_port = htons((unsigned short) port);
}

static inline unsigned int sin_get_port(union sockaddr_union *so)
{
#ifdef HAVE_IPV6
	if (so->sin.sin_family == AF_INET6)
		return ntohs(so->sin6.sin6_port);
#endif
	if (so->sin.sin_family == AF_INET)
		return ntohs(so->sin.sin_port);

	return 0;
}

int net_connect_ip(const struct ip_addr *ip, unsigned int port,
		   const struct ip_addr *my_ip)
{
	union sockaddr_union so;
	int fd, ret, opt = 1;

	if (my_ip != NULL && ip->family != my_ip->family) {
		i_warning("net_connect_ip(): ip->family != my_ip->family");
                my_ip = NULL;
	}

	/* create the socket */
	memset(&so, 0, sizeof(so));
        so.sin.sin_family = ip->family;
	fd = socket(ip->family, SOCK_STREAM, 0);

	if (fd == -1) {
		i_error("socket() failed: %m");
		return -1;
	}

	/* set socket options */
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
	net_set_nonblock(fd, TRUE);

	/* set our own address */
	if (my_ip != NULL) {
		sin_set_ip(&so, my_ip);
		if (bind(fd, &so.sa, SIZEOF_SOCKADDR(so)) == -1) {
			/* failed, set it back to INADDR_ANY */
			i_error("bind(%s) failed: %m", net_ip2addr(my_ip));
			close_keep_errno(fd);
			return -1;
		}
	}

	/* connect */
	sin_set_ip(&so, ip);
	sin_set_port(&so, port);
	ret = connect(fd, &so.sa, SIZEOF_SOCKADDR(so));

#ifndef WIN32
	if (ret < 0 && errno != EINPROGRESS)
#else
	if (ret < 0 && WSAGetLastError() != WSAEWOULDBLOCK)
#endif
	{
                close_keep_errno(fd);
		return -1;
	}

	return fd;
}

int net_connect_unix(const char *path)
{
	union {
		struct sockaddr sa;
		struct sockaddr_un un;
	} sa;
	int fd, ret;

	memset(&sa, 0, sizeof(sa));
	sa.un.sun_family = AF_UNIX;
	if (strocpy(sa.un.sun_path, path, sizeof(sa.un.sun_path)) < 0) {
		/* too long path */
		errno = EINVAL;
		return -1;
	}

	/* create the socket */
	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		i_error("socket(%s) failed: %m", path);
		return -1;
	}

	net_set_nonblock(fd, TRUE);

	/* connect */
	ret = connect(fd, &sa.sa, sizeof(sa));
	if (ret < 0 && errno != EINPROGRESS) {
                close_keep_errno(fd);
		return -1;
	}

	return fd;
}

void net_disconnect(int fd)
{
	if (close(fd) < 0)
		i_error("net_disconnect() failed: %m");
}

void net_set_nonblock(int fd, bool nonblock)
{
	if (fd_set_nonblock(fd, nonblock) < 0)
		i_fatal("fd_set_nonblock(%d) failed: %m", fd);
}

int net_set_cork(int fd ATTR_UNUSED, bool cork ATTR_UNUSED)
{
#ifdef TCP_CORK
	int val = cork;

	return setsockopt(fd, IPPROTO_TCP, TCP_CORK, &val, sizeof(val));
#else
	errno = ENOPROTOOPT;
	return -1;
#endif
}

void net_get_ip_any4(struct ip_addr *ip)
{
	ip->family = AF_INET;
	ip->u.ip4.s_addr = INADDR_ANY;
}

void net_get_ip_any6(struct ip_addr *ip)
{
#ifdef HAVE_IPV6
	ip->family = AF_INET6;
	ip->u.ip6 = in6addr_any;
#else
	memset(ip, 0, sizeof(struct ip_addr));
#endif
}

int net_listen(const struct ip_addr *my_ip, unsigned int *port, int backlog)
{
	union sockaddr_union so;
	int ret, fd, opt = 1;
	socklen_t len;

	memset(&so, 0, sizeof(so));
	sin_set_port(&so, *port);
	sin_set_ip(&so, my_ip);

	/* create the socket */
	fd = socket(so.sin.sin_family, SOCK_STREAM, 0);
#ifdef HAVE_IPV6
	if (fd == -1 && (errno == EINVAL || errno == EAFNOSUPPORT)) {
		/* IPv6 is not supported by OS */
		so.sin.sin_family = AF_INET;
		so.sin.sin_addr.s_addr = INADDR_ANY;

		fd = socket(AF_INET, SOCK_STREAM, 0);
	}
#endif
	if (fd == -1) {
		i_error("socket() failed: %m");
		return -1;
	}

	/* set socket options */
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

	/* if using IPv6, bind both on the IPv4 and IPv6 addresses */
#ifdef IPV6_V6ONLY
	if (so.sin.sin_family == AF_INET6) {
		opt = 0;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
	}
#endif
	/* specify the address/port we want to listen in */
	ret = bind(fd, &so.sa, SIZEOF_SOCKADDR(so));
	if (ret < 0) {
		if (errno != EADDRINUSE) {
			i_error("bind(%s, %u) failed: %m",
				net_ip2addr(my_ip), *port);
		}
	} else {
		/* get the actual port we started listen */
		len = SIZEOF_SOCKADDR(so);
		ret = getsockname(fd, &so.sa, &len);
		if (ret >= 0) {
			*port = sin_get_port(&so);

			/* start listening */
			if (listen(fd, backlog) >= 0)
				return fd;

			if (errno != EADDRINUSE)
				i_error("listen() failed: %m");
		}
	}

        /* error */
	close_keep_errno(fd);
	return -1;
}

int net_listen_unix(const char *path, int backlog)
{
	union {
		struct sockaddr sa;
		struct sockaddr_un un;
	} sa;
	int fd;

	memset(&sa, 0, sizeof(sa));
	sa.un.sun_family = AF_UNIX;
	if (strocpy(sa.un.sun_path, path, sizeof(sa.un.sun_path)) < 0) {
		/* too long path */
		errno = EINVAL;
		return -1;
	}

	/* create the socket */
	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		i_error("socket() failed: %m");
		return -1;
	}

	/* bind */
	if (bind(fd, &sa.sa, sizeof(sa)) < 0) {
		if (errno != EADDRINUSE)
			i_error("bind(%s) failed: %m", path);
	} else {
		/* start listening */
		if (listen(fd, backlog) == 0)
			return fd;

		if (errno != EADDRINUSE)
			i_error("listen() failed: %m");
	}

	close_keep_errno(fd);
	return -1;
}

int net_accept(int fd, struct ip_addr *addr, unsigned int *port)
{
	union sockaddr_union so;
	int ret;
	socklen_t addrlen;

	i_assert(fd >= 0);

	addrlen = sizeof(so);
	ret = accept(fd, &so.sa, &addrlen);

	if (ret < 0) {
		if (errno == EAGAIN || errno == ECONNABORTED)
			return -1;
		else
			return -2;
	}

	if (addr != NULL) sin_get_ip(&so, addr);
	if (port != NULL) *port = sin_get_port(&so);

	return ret;
}

ssize_t net_receive(int fd, void *buf, size_t len)
{
	ssize_t ret;

	i_assert(fd >= 0);
	i_assert(len <= SSIZE_T_MAX);

	ret = read(fd, buf, len);
	if (ret == 0) {
		/* disconnected */
		errno = 0;
		return -2;
	}

	if (ret < 0) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;

		if (errno == ECONNRESET || errno == ETIMEDOUT) {
                        /* treat as disconnection */
			return -2;
		}
	}

	return ret;
}

ssize_t net_transmit(int fd, const void *data, size_t len)
{
        ssize_t ret;

	i_assert(fd >= 0);
	i_assert(len <= SSIZE_T_MAX);

	ret = send(fd, data, len, 0);
	if (ret == -1 && (errno == EINTR || errno == EAGAIN))
		return 0;

	if (errno == EPIPE)
		return -2;

        return ret;
}

int net_gethostbyname(const char *addr, struct ip_addr **ips,
		      unsigned int *ips_count)
{
	/* @UNSAFE */
#ifdef HAVE_IPV6
	union sockaddr_union *so;
	struct addrinfo hints, *ai, *origai;
	int host_error;
#else
	struct hostent *hp;
#endif
        int count;

	*ips = NULL;
        *ips_count = 0;

#ifdef HAVE_IPV6
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;

	/* save error to host_error for later use */
	host_error = getaddrinfo(addr, NULL, &hints, &ai);
	if (host_error != 0)
		return host_error;

        /* get number of IPs */
        origai = ai;
	for (count = 0; ai != NULL; ai = ai->ai_next)
                count++;

        *ips_count = count;
        *ips = t_malloc(sizeof(struct ip_addr) * count);

        count = 0;
	for (ai = origai; ai != NULL; ai = ai->ai_next, count++) {
		so = (union sockaddr_union *) ai->ai_addr;

		sin_get_ip(so, &(*ips)[count]);
	}
	freeaddrinfo(origai);
#else
	hp = gethostbyname(addr);
	if (hp == NULL)
		return h_errno;

        /* get number of IPs */
	count = 0;
	while (hp->h_addr_list[count] != NULL)
		count++;

        *ips_count = count;
        *ips = t_malloc(sizeof(struct ip_addr) * count);

	while (count > 0) {
		count--;

		(*ips)[count].family = AF_INET;
		memcpy(&(*ips)[count].u.ip4, hp->h_addr_list[count],
		       sizeof((*ips)[count].u.ip4));
	}
#endif

	return 0;
}

int net_getsockname(int fd, struct ip_addr *addr, unsigned int *port)
{
	union sockaddr_union so;
	socklen_t addrlen;

	i_assert(fd >= 0);

	addrlen = sizeof(so);
	if (getsockname(fd, &so.sa, &addrlen) == -1)
		return -1;

        if (addr != NULL) sin_get_ip(&so, addr);
	if (port != NULL) *port = sin_get_port(&so);

	return 0;
}

int net_getpeername(int fd, struct ip_addr *addr, unsigned int *port)
{
	union sockaddr_union so;
	socklen_t addrlen;

	i_assert(fd >= 0);

	addrlen = sizeof(so);
	if (getpeername(fd, &so.sa, &addrlen) == -1)
		return -1;

        if (addr != NULL) sin_get_ip(&so, addr);
	if (port != NULL) *port = sin_get_port(&so);

	return 0;
}

const char *net_ip2addr(const struct ip_addr *ip)
{
#ifdef HAVE_IPV6
	char addr[MAX_IP_LEN+1];

	addr[MAX_IP_LEN] = '\0';
	if (inet_ntop(ip->family, &ip->u.ip6, addr, MAX_IP_LEN) == NULL)
		return NULL;

	return t_strdup(addr);
#else
	unsigned long ip4;

	if (ip->family != AF_INET)
		return NULL;

	ip4 = ntohl(ip->u.ip4.s_addr);
	return t_strdup_printf("%lu.%lu.%lu.%lu",
			       (ip4 & 0xff000000UL) >> 24,
			       (ip4 & 0x00ff0000) >> 16,
			       (ip4 & 0x0000ff00) >> 8,
			       (ip4 & 0x000000ff));
#endif
}

int net_addr2ip(const char *addr, struct ip_addr *ip)
{
	if (strchr(addr, ':') != NULL) {
		/* IPv6 */
		ip->family = AF_INET6;
#ifdef HAVE_IPV6
		if (inet_pton(AF_INET6, addr, &ip->u.ip6) == 0)
			return -1;
#else
		ip->u.ip4.s_addr = 0;
#endif
 	} else {
		/* IPv4 */
		ip->family = AF_INET;
		if (inet_aton(addr, &ip->u.ip4) == 0)
			return -1;
	}

	return 0;
}

int net_ipv6_mapped_ipv4_convert(const struct ip_addr *src,
				 struct ip_addr *dest)
{
#ifdef HAVE_IPV6
	static uint8_t v4_prefix[] =
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

	if (!IPADDR_IS_V6(src))
		return -1;
	if (memcmp(src->u.ip6.s6_addr, v4_prefix, sizeof(v4_prefix)) != 0)
		return -1;

	dest->family = AF_INET;
	memcpy(&dest->u.ip6, &src->u.ip6.s6_addr[3*4], 4);
	return 0;
#else
	return -1;
#endif
}

int net_geterror(int fd)
{
	int data;
	socklen_t len = sizeof(data);

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &data, &len) == -1)
		return -1;

	return data;
}

const char *net_gethosterror(int error)
{
#ifdef HAVE_IPV6
	i_assert(error != 0);

	return gai_strerror(error);
#else
	switch (error) {
	case HOST_NOT_FOUND:
		return "Host not found";
	case NO_ADDRESS:
		return "No IP address found for name";
	case NO_RECOVERY:
		return "A non-recovable name server error occurred";
	case TRY_AGAIN:
		return "A temporary error on an authoritative name server";
	}

	/* unknown error */
	return NULL;
#endif
}

int net_hosterror_notfound(int error)
{
#ifdef HAVE_IPV6
#ifdef EAI_NODATA /* NODATA is depricated */
	return error != 1 && (error == EAI_NONAME || error == EAI_NODATA);
#else
	return error != 1 && (error == EAI_NONAME);
#endif
#else
	return error == HOST_NOT_FOUND || error == NO_ADDRESS;
#endif
}

const char *net_getservbyport(unsigned short port)
{
	struct servent *entry;

	entry = getservbyport(htons(port), "tcp");
	return entry == NULL ? NULL : entry->s_name;
}

bool is_ipv4_address(const char *addr)
{
	while (*addr != '\0') {
		if (*addr != '.' && !i_isdigit(*addr))
			return FALSE;
                addr++;
	}

	return TRUE;
}

bool is_ipv6_address(const char *addr)
{
	while (*addr != '\0') {
		if (*addr != ':' && !i_isxdigit(*addr))
			return FALSE;
                addr++;
	}

	return TRUE;
}
