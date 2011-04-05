/* Copyright (c) 1999-2011 Dovecot authors, see the included COPYING file */

#define _GNU_SOURCE /* For Linux's struct ucred */
#include "lib.h"
#include "close-keep-errno.h"
#include "fd-set-nonblock.h"
#include "time-util.h"
#include "network.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#ifdef HAVE_UCRED_H
#  include <ucred.h> /* for getpeerucred() */
#endif

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
	return net_ip_cmp(ip1, ip2) == 0;
}

int net_ip_cmp(const struct ip_addr *ip1, const struct ip_addr *ip2)
{
	if (ip1->family != ip2->family)
		return ip1->family - ip2->family;

#ifdef HAVE_IPV6
	if (ip1->family == AF_INET6)
		return memcmp(&ip1->u.ip6, &ip2->u.ip6, sizeof(ip1->u.ip6));
#endif

	return memcmp(&ip1->u.ip4, &ip2->u.ip4, sizeof(ip1->u.ip4));
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
	/* IP structs may be sent across processes. Clear the whole struct
	   first to make sure it won't leak any data across processes. */
	memset(ip, 0, sizeof(*ip));

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

#ifdef __FreeBSD__
static int
net_connect_ip_full_freebsd(const struct ip_addr *ip, unsigned int port,
			    const struct ip_addr *my_ip, bool blocking);

static int net_connect_ip_full(const struct ip_addr *ip, unsigned int port,
			       const struct ip_addr *my_ip, bool blocking)
{
	int fd, try;

	for (try = 0;;) {
		fd = net_connect_ip_full_freebsd(ip, port, my_ip, blocking);
		if (fd != -1 || ++try == 5 ||
		    (errno != EADDRINUSE && errno != EACCES))
			break;
		/*
		   This may be just a temporary problem:

		   EADDRINUSE: busy
		   EACCES: pf may cause this if another connection used
		           the same port recently
		*/
	}
	return fd;
}
/* then some kludging: */
#define net_connect_ip_full net_connect_ip_full_freebsd
#endif

static int net_connect_ip_full(const struct ip_addr *ip, unsigned int port,
			       const struct ip_addr *my_ip, bool blocking)
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
	if (!blocking)
		net_set_nonblock(fd, TRUE);

	/* set our own address */
	if (my_ip != NULL) {
		sin_set_ip(&so, my_ip);
		if (bind(fd, &so.sa, SIZEOF_SOCKADDR(so)) == -1) {
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
#ifdef __FreeBSD__
#  undef net_connect_ip_full
#endif

int net_connect_ip(const struct ip_addr *ip, unsigned int port,
		   const struct ip_addr *my_ip)
{
	return net_connect_ip_full(ip, port, my_ip, FALSE);
}

int net_connect_ip_blocking(const struct ip_addr *ip, unsigned int port,
			    const struct ip_addr *my_ip)
{
	return net_connect_ip_full(ip, port, my_ip, TRUE);
}

int net_try_bind(const struct ip_addr *ip)
{
	union sockaddr_union so;
	int fd;

	/* create the socket */
	memset(&so, 0, sizeof(so));
        so.sin.sin_family = ip->family;
	fd = socket(ip->family, SOCK_STREAM, 0);
	if (fd == -1) {
		i_error("socket() failed: %m");
		return -1;
	}

	sin_set_ip(&so, ip);
	if (bind(fd, &so.sa, SIZEOF_SOCKADDR(so)) == -1) {
		close_keep_errno(fd);
		return -1;
	}
	(void)close(fd);
	return 0;
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
	if (i_strocpy(sa.un.sun_path, path, sizeof(sa.un.sun_path)) < 0) {
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

int net_connect_unix_with_retries(const char *path, unsigned int msecs)
{
	struct timeval start, now;
	int fd;

	if (gettimeofday(&start, NULL) < 0)
		i_panic("gettimeofday() failed: %m");

	do {
		fd = net_connect_unix(path);
		if (fd != -1 || (errno != EAGAIN && errno != ECONNREFUSED))
			break;

		/* busy. wait for a while. */
		usleep(((rand() % 10) + 1) * 10000);
		if (gettimeofday(&now, NULL) < 0)
			i_panic("gettimeofday() failed: %m");
	} while (timeval_diff_msecs(&now, &start) < (int)msecs);
	return fd;
}

void net_disconnect(int fd)
{
	/* FreeBSD's close() fails with ECONNRESET if socket still has unsent
	   data in transmit buffer. We don't care. */
	if (close(fd) < 0 && errno != ECONNRESET)
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
	if (fd == -1 && my_ip == NULL &&
	    (errno == EINVAL || errno == EAFNOSUPPORT)) {
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

	/* If using IPv6, bind only to IPv6 if possible. This avoids
	   ambiguities with IPv4-mapped IPv6 addresses. */
#ifdef IPV6_V6ONLY
	if (so.sin.sin_family == AF_INET6) {
		opt = 1;
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
	if (i_strocpy(sa.un.sun_path, path, sizeof(sa.un.sun_path)) < 0) {
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

int net_listen_unix_unlink_stale(const char *path, int backlog)
{
	unsigned int i = 0;
	int fd;

	while ((fd = net_listen_unix(path, backlog)) == -1) {
		if (errno != EADDRINUSE || ++i == 2)
			return -1;

		/* see if it really exists */
		fd = net_connect_unix(path);
		if (fd != -1 || errno != ECONNREFUSED) {
			if (fd != -1) (void)close(fd);
			errno = EADDRINUSE;
			return -1;
		}

		/* delete and try again */
		if (unlink(path) < 0 && errno != ENOENT) {
			i_error("unlink(%s) failed: %m", path);
			errno = EADDRINUSE;
			return -1;
		}
	}
	return fd;
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
	if (so.sin.sin_family == AF_UNIX) {
		if (addr != NULL)
			memset(addr, 0, sizeof(*addr));
		if (port != NULL) *port = 0;
	} else {
		if (addr != NULL) sin_get_ip(&so, addr);
		if (port != NULL) *port = sin_get_port(&so);
	}
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

	if (unlikely(ret < 0)) {
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
	if (unlikely(ret == -1 && (errno == EINTR || errno == EAGAIN)))
		return 0;

	if (unlikely(errno == EPIPE))
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
	if (so.sin.sin_family == AF_UNIX) {
		if (addr != NULL)
			memset(addr, 0, sizeof(*addr));
		if (port != NULL) *port = 0;
	} else {
		if (addr != NULL) sin_get_ip(&so, addr);
		if (port != NULL) *port = sin_get_port(&so);
	}
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
	if (so.sin.sin_family == AF_UNIX) {
		if (addr != NULL)
			memset(addr, 0, sizeof(*addr));
		if (port != NULL) *port = 0;
	} else {
		if (addr != NULL) sin_get_ip(&so, addr);
		if (port != NULL) *port = sin_get_port(&so);
	}
	return 0;
}

int net_getunixname(int fd, const char **name_r)
{
	struct sockaddr_un sa;
	socklen_t addrlen = sizeof(sa);

	if (getsockname(fd, (void *)&sa, &addrlen) < 0)
		return -1;
	if (sa.sun_family != AF_UNIX) {
		errno = ENOTSOCK;
		return -1;
	}
	*name_r = t_strdup(sa.sun_path);
	return 0;
}

int net_getunixcred(int fd, struct net_unix_cred *cred_r)
{
#if defined(SO_PEERCRED)
	/* Linux */
	struct ucred ucred;
	socklen_t len = sizeof(ucred);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) < 0) {
		i_error("getsockopt(SO_PEERCRED) failed: %m");
		return -1;
	}
	cred_r->uid = ucred.uid;
	cred_r->gid = ucred.gid;
	return 0;
#elif defined(HAVE_GETPEEREID)
	/* OSX 10.4+, FreeBSD 4.6+, OpenBSD 3.0+, NetBSD 5.0+ */
	if (getpeereid(fd, &cred_r->uid, &cred_r->gid) < 0) {
		i_error("getpeereid() failed: %m");
		return -1;
	}
	return 0;
#elif defined(HAVE_GETPEERUCRED)
	/* Solaris */
	ucred_t *ucred;

	if (getpeerucred(fd, &ucred) < 0) {
		i_error("getpeerucred() failed: %m");
		return -1;
	}
	cred_r->uid = ucred_geteuid(ucred);
	cred_r->gid = ucred_getrgid(ucred);
	ucred_free(ucred);

	if (cred_r->uid == (uid_t)-1 ||
	    cred_r->gid == (gid_t)-1) {
		errno = EINVAL;
		return -1;
	}
	return 0;
#else
	errno = EINVAL;
	return -1;
#endif
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
	int ret;

	if (strchr(addr, ':') != NULL) {
		/* IPv6 */
		ip->family = AF_INET6;
#ifdef HAVE_IPV6
		T_BEGIN {
			if (addr[0] == '[') {
				/* allow [ipv6 addr] */
				unsigned int len = strlen(addr);
				if (addr[len-1] == ']')
					addr = t_strndup(addr+1, len-2);
			}
			ret = inet_pton(AF_INET6, addr, &ip->u.ip6);
		} T_END;
		if (ret == 0)
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
		return "A non-recoverable name server error occurred";
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
	bool have_prefix = FALSE;

	if (*addr == '[') {
		have_prefix = TRUE;
		addr++;
	}
	while (*addr != '\0') {
		if (*addr != ':' && !i_isxdigit(*addr)) {
			if (have_prefix && *addr == ']' && addr[1] == '\0')
				break;
			return FALSE;
		}
                addr++;
	}

	return TRUE;
}

int net_parse_range(const char *network, struct ip_addr *ip_r,
		    unsigned int *bits_r)
{
	const char *p;
	unsigned int bits, max_bits;

	p = strchr(network, '/');
	if (p != NULL)
		network = t_strdup_until(network, p++);

	if (net_addr2ip(network, ip_r) < 0)
		return -1;

	max_bits = IPADDR_IS_V4(ip_r) ? 32 : 128;
	if (p == NULL) {
		/* full IP address must match */
		bits = max_bits;
	} else {
		/* get the network mask */
		if (str_to_uint(p, &bits) < 0 || bits > max_bits)
			return -1;
	}
	*bits_r = bits;
	return 0;
}

bool net_is_in_network(const struct ip_addr *ip,
		       const struct ip_addr *net_ip, unsigned int bits)
{
	struct ip_addr tmp_ip;
	const uint32_t *ip1, *ip2;
	uint32_t mask, i1, i2;
	unsigned int pos, i;

	if (net_ipv6_mapped_ipv4_convert(ip, &tmp_ip) == 0) {
		/* IPv4 address mapped disguised as IPv6 address */
		ip = &tmp_ip;
	}

	if (IPADDR_IS_V4(ip) != IPADDR_IS_V4(net_ip)) {
		/* one is IPv6 and one is IPv4 */
		return FALSE;
	}
	i_assert(IPADDR_IS_V6(ip) == IPADDR_IS_V6(net_ip));

	if (IPADDR_IS_V4(ip)) {
		ip1 = &ip->u.ip4.s_addr;
		ip2 = &net_ip->u.ip4.s_addr;
	} else {
#ifdef HAVE_IPV6
		ip1 = (const void *)&ip->u.ip6;
		ip2 = (const void *)&net_ip->u.ip6;
#else
		/* shouldn't get here */
		return FALSE;
#endif
	}

	/* check first the full 32bit ints */
	for (pos = 0, i = 0; pos + 32 <= bits; pos += 32, i++) {
		if (ip1[i] != ip2[i])
			return FALSE;
	}
	i1 = htonl(ip1[i]);
	i2 = htonl(ip2[i]);

	/* check the last full bytes */
	for (mask = 0xff000000; pos + 8 <= bits; pos += 8, mask >>= 8) {
		if ((i1 & mask) != (i2 & mask))
			return FALSE;
	}

	/* check the last bits, they're reversed in bytes */
	bits -= pos;
	for (mask = 0x80000000 >> (pos % 32); bits > 0; bits--, mask >>= 1) {
		if ((i1 & mask) != (i2 & mask))
			return FALSE;
	}
	return TRUE;
}
