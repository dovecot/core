/* Copyright (c) 1999-2018 Dovecot authors, see the included COPYING file */

#define _GNU_SOURCE /* For Linux's struct ucred */
#include "lib.h"
#include "time-util.h"
#include "net.h"

#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#if defined(HAVE_UCRED_H)
#  include <ucred.h> /* for getpeerucred() */
#elif defined(HAVE_SYS_UCRED_H)
#  include <sys/ucred.h> /* for FreeBSD struct xucred */
#endif

union sockaddr_union {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

union sockaddr_union_unix {
	struct sockaddr sa;
	struct sockaddr_un un;
};

#define SIZEOF_SOCKADDR(so) ((so).sa.sa_family == AF_INET6 ? \
	sizeof(so.sin6) : sizeof(so.sin))

#if !defined(HAVE_GETPEEREID) && !defined(SO_PEERCRED) && !defined(HAVE_GETPEERUCRED) && defined(MSG_WAITALL) && defined(LOCAL_CREDS)
#  define NEEDS_LOCAL_CREDS 1
#else
#  undef NEEDS_LOCAL_CREDS
#endif

/* If connect() fails with EADDRNOTAVAIL (or some others on FreeBSD), retry it
   this many times.

   This is needed on busy systems kernel may assign the same source port to two
   sockets at bind() stage, which is what we generally want to allow more than
   64k outgoing connections to different destinations. However, at bind() stage
   the kernel doesn't know the destination yet. So it's possible that it
   assigns the same source port to two (or more) sockets that have the same
   destination IP+port as well. In this case connect() will fail with
   EADDRNOTAVAIL. We'll need to retry this and hope that the next attempt won't
   conflict. */
#define MAX_CONNECT_RETRIES 20

bool net_ip_compare(const struct ip_addr *ip1, const struct ip_addr *ip2)
{
	return net_ip_cmp(ip1, ip2) == 0;
}

int net_ip_cmp(const struct ip_addr *ip1, const struct ip_addr *ip2)
{
	if (ip1->family != ip2->family)
		return ip1->family - ip2->family;

	switch (ip1->family) {
	case AF_INET6:
		return memcmp(&ip1->u.ip6, &ip2->u.ip6, sizeof(ip1->u.ip6));
	case AF_INET:
		return memcmp(&ip1->u.ip4, &ip2->u.ip4, sizeof(ip1->u.ip4));
	default:
		break;
	}
	return 0;
}

unsigned int net_ip_hash(const struct ip_addr *ip)
{
        const unsigned char *p;
	unsigned int len, g, h = 0;

	if (ip->family == AF_INET6) {
		p = ip->u.ip6.s6_addr;
		len = sizeof(ip->u.ip6);
	} else
	{
		return ip->u.ip4.s_addr;
	}

	for (; len > 0; len--, p++) {
		h = (h << 4) + *p;
		if ((g = h & 0xf0000000UL) != 0) {
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
		so->sin6.sin6_family = AF_INET6;
		so->sin6.sin6_addr = in6addr_any;
		return;
	}

	so->sin.sin_family = ip->family;
	if (ip->family == AF_INET6)
		memcpy(&so->sin6.sin6_addr, &ip->u.ip6, sizeof(ip->u.ip6));
	else
		memcpy(&so->sin.sin_addr, &ip->u.ip4, sizeof(ip->u.ip4));
}

static inline void
sin_get_ip(const union sockaddr_union *so, struct ip_addr *ip)
{
	/* IP structs may be sent across processes. Clear the whole struct
	   first to make sure it won't leak any data across processes. */
	i_zero(ip);

	ip->family = so->sin.sin_family;

	if (ip->family == AF_INET6)
		memcpy(&ip->u.ip6, &so->sin6.sin6_addr, sizeof(ip->u.ip6));
	else
	if (ip->family == AF_INET)
		memcpy(&ip->u.ip4, &so->sin.sin_addr, sizeof(ip->u.ip4));
	else
		i_zero(&ip->u);
}

static inline void sin_set_port(union sockaddr_union *so, in_port_t port)
{
	if (so->sin.sin_family == AF_INET6)
                so->sin6.sin6_port = htons(port);
	else
		so->sin.sin_port = htons(port);
}

static inline in_port_t sin_get_port(union sockaddr_union *so)
{
	if (so->sin.sin_family == AF_INET6)
		return ntohs(so->sin6.sin6_port);
	if (so->sin.sin_family == AF_INET)
		return ntohs(so->sin.sin_port);

	return 0;
}

static int net_connect_ip_once(const struct ip_addr *ip, in_port_t port,
			       const struct ip_addr *my_ip, int sock_type, bool blocking)
{
	union sockaddr_union so;
	int fd, ret, opt = 1;

	if (my_ip != NULL && ip->family != my_ip->family) {
		i_warning("net_connect_ip(): ip->family != my_ip->family");
                my_ip = NULL;
	}

	/* create the socket */
	i_zero(&so);
        so.sin.sin_family = ip->family;
	fd = socket(ip->family, sock_type, 0);

	if (fd == -1) {
		i_error("socket() failed: %m");
		return -1;
	}

	/* set socket options */
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (sock_type == SOCK_STREAM)
		(void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
	if (!blocking)
		net_set_nonblock(fd, TRUE);

	/* set our own address */
	if (my_ip != NULL) {
		sin_set_ip(&so, my_ip);
		if (bind(fd, &so.sa, SIZEOF_SOCKADDR(so)) == -1) {
			i_error("bind(%s) failed: %m", net_ip2addr(my_ip));
			i_close_fd(&fd);
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
                i_close_fd(&fd);
		return -1;
	}

	return fd;
}

static int net_connect_ip_full(const struct ip_addr *ip, in_port_t port,
			       const struct ip_addr *my_ip, int sock_type,
			       bool blocking)
{
	int fd, try;

	for (try = 0;;) {
		fd = net_connect_ip_once(ip, port, my_ip, sock_type, blocking);
		if (fd != -1 || try++ >= MAX_CONNECT_RETRIES ||
		    (errno != EADDRNOTAVAIL
#ifdef __FreeBSD__
		     /* busy */
		     && errno != EADDRINUSE
		     /* pf may cause this if another connection used
			the same port recently */
		     && errno != EACCES
#endif
		    ))
			break;
	}
	return fd;
}

int net_connect_ip(const struct ip_addr *ip, in_port_t port,
		   const struct ip_addr *my_ip)
{
	return net_connect_ip_full(ip, port, my_ip, SOCK_STREAM, FALSE);
}

int net_connect_ip_blocking(const struct ip_addr *ip, in_port_t port,
			    const struct ip_addr *my_ip)
{
	return net_connect_ip_full(ip, port, my_ip, SOCK_STREAM, TRUE);
}

int net_connect_udp(const struct ip_addr *ip, in_port_t port,
			       const struct ip_addr *my_ip)
{
	return net_connect_ip_full(ip, port, my_ip, SOCK_DGRAM, FALSE);
}

int net_try_bind(const struct ip_addr *ip)
{
	union sockaddr_union so;
	int fd;

	/* create the socket */
	i_zero(&so);
        so.sin.sin_family = ip->family;
	fd = socket(ip->family, SOCK_STREAM, 0);
	if (fd == -1) {
		i_error("socket() failed: %m");
		return -1;
	}

	sin_set_ip(&so, ip);
	if (bind(fd, &so.sa, SIZEOF_SOCKADDR(so)) == -1) {
		i_close_fd(&fd);
		return -1;
	}
	i_close_fd(&fd);
	return 0;
}

int net_connect_unix(const char *path)
{
	union sockaddr_union_unix sa;
	int fd, ret;

	i_zero(&sa);
	sa.un.sun_family = AF_UNIX;
	if (i_strocpy(sa.un.sun_path, path, sizeof(sa.un.sun_path)) < 0) {
		/* too long path */
#ifdef ENAMETOOLONG
		errno = ENAMETOOLONG;
#else
		errno = EINVAL;
#endif
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
                i_close_fd(&fd);
		return -1;
	}

#ifdef NEEDS_LOCAL_CREDS
	{
		int on = 1;
		if (setsockopt(fd, 0, LOCAL_CREDS, &on, sizeof on)) {
			i_error("setsockopt(LOCAL_CREDS) failed: %m");
			return -1;
		}
	}
#endif

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
		usleep(i_rand_minmax(1, 10) * 10000);
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
	fd_set_nonblock(fd, nonblock);
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

int net_set_tcp_nodelay(int fd, bool nodelay)
{
	int val = nodelay;

	return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
}

int net_set_send_buffer_size(int fd, size_t size)
{
	int opt;

	if (size > INT_MAX) {
		errno = EINVAL;
		return -1;
	}
	opt = (int)size;
	return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));
}

int net_set_recv_buffer_size(int fd, size_t size)
{
	int opt;

	if (size > INT_MAX) {
		errno = EINVAL;
		return -1;
	}
	opt = (int)size;
	return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
}

const struct ip_addr net_ip4_any = {
	.family = AF_INET,
	.u.ip4.s_addr = INADDR_ANY
};

const struct ip_addr net_ip6_any = {
	.family = AF_INET6,
	.u.ip6 = IN6ADDR_ANY_INIT
};

const struct ip_addr net_ip4_loopback = {
	.family = AF_INET,
	.u.ip4.s_addr = INADDR_LOOPBACK
};

const struct ip_addr net_ip6_loopback = {
	.family = AF_INET6,
	.u.ip6 = IN6ADDR_LOOPBACK_INIT
};

int net_listen(const struct ip_addr *my_ip, in_port_t *port, int backlog)
{
	enum net_listen_flags flags = 0;

	return net_listen_full(my_ip, port, &flags, backlog);
}

int net_listen_full(const struct ip_addr *my_ip, in_port_t *port,
		    enum net_listen_flags *flags, int backlog)
{
	union sockaddr_union so;
	int ret, fd, opt = 1;
	socklen_t len;

	i_zero(&so);
	sin_set_port(&so, *port);
	sin_set_ip(&so, my_ip);

	/* create the socket */
	fd = socket(so.sin.sin_family, SOCK_STREAM, 0);
	if (fd == -1 && my_ip == NULL &&
	    (errno == EINVAL || errno == EAFNOSUPPORT)) {
		/* IPv6 is not supported by OS */
		so.sin.sin_family = AF_INET;
		so.sin.sin_addr.s_addr = INADDR_ANY;

		fd = socket(AF_INET, SOCK_STREAM, 0);
	}
	if (fd == -1) {
		i_error("socket() failed: %m");
		return -1;
	}

	/* set socket options */
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	(void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

	if ((*flags & NET_LISTEN_FLAG_REUSEPORT) != 0) {
#ifdef SO_REUSEPORT
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
			       &opt, sizeof(opt)) < 0)
#endif
			*flags &= ~NET_LISTEN_FLAG_REUSEPORT;
	}

	/* If using IPv6, bind only to IPv6 if possible. This avoids
	   ambiguities with IPv4-mapped IPv6 addresses. */
#ifdef IPV6_V6ONLY
	if (so.sin.sin_family == AF_INET6) {
		opt = 1;
		(void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
	}
#endif
	/* specify the address/port we want to listen in */
	ret = bind(fd, &so.sa, SIZEOF_SOCKADDR(so));
	if (ret < 0) {
		if (errno != EADDRINUSE) {
			i_error("bind(%s, %u) failed: %m",
				my_ip == NULL ? "" : net_ip2addr(my_ip), *port);
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
	i_close_fd(&fd);
	return -1;
}

int net_listen_unix(const char *path, int backlog)
{
	union {
		struct sockaddr sa;
		struct sockaddr_un un;
	} sa;
	int fd;

	i_zero(&sa);
	sa.un.sun_family = AF_UNIX;
	if (i_strocpy(sa.un.sun_path, path, sizeof(sa.un.sun_path)) < 0) {
		/* too long path */
		errno = EOVERFLOW;
		return -1;
	}

	/* create the socket */
	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		i_error("socket() failed: %m");
		return -1;
	}

#ifdef NEEDS_LOCAL_CREDS
	{
		int on = 1;
		if (setsockopt(fd, 0, LOCAL_CREDS, &on, sizeof on)) {
			i_error("setsockopt(LOCAL_CREDS) failed: %m");
			return -1;
		}
	}
#endif

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

	i_close_fd(&fd);
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
			i_close_fd(&fd);
			errno = EADDRINUSE;
			return -1;
		}

		/* delete and try again */
		if (i_unlink_if_exists(path) < 0) {
			errno = EADDRINUSE;
			return -1;
		}
	}
	return fd;
}

int net_accept(int fd, struct ip_addr *addr_r, in_port_t *port_r)
{
	union sockaddr_union so;
	int ret;
	socklen_t addrlen;

	i_assert(fd >= 0);

	i_zero(&so);
	addrlen = sizeof(so);
	ret = accept(fd, &so.sa, &addrlen);

	if (ret < 0) {
		if (errno == EAGAIN || errno == ECONNABORTED)
			return -1;
		else
			return -2;
	}
	if (so.sin.sin_family == AF_UNIX) {
		if (addr_r != NULL)
			i_zero(addr_r);
		if (port_r != NULL) *port_r = 0;
	} else {
		if (addr_r != NULL) sin_get_ip(&so, addr_r);
		if (port_r != NULL) *port_r = sin_get_port(&so);
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

int net_gethostbyname(const char *addr, struct ip_addr **ips,
		      unsigned int *ips_count)
{
	/* @UNSAFE */
	union sockaddr_union *so;
	struct addrinfo hints, *ai, *origai;
	struct ip_addr ip;
	int host_error;
        int count;

	*ips = NULL;
        *ips_count = 0;

	/* support [ipv6] style addresses here so they work globally */
	if (addr[0] == '[' && net_addr2ip(addr, &ip) == 0) {
		*ips_count = 1;
		*ips = t_new(struct ip_addr, 1);
		**ips = ip;
		return 0;
	}

	i_zero(&hints);
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
        *ips = t_new(struct ip_addr, count);

        count = 0;
	for (ai = origai; ai != NULL; ai = ai->ai_next, count++) {
		so = (union sockaddr_union *) ai->ai_addr;

		sin_get_ip(so, &(*ips)[count]);
	}
	freeaddrinfo(origai);

	return 0;
}

int net_gethostbyaddr(const struct ip_addr *ip, const char **name_r)
{
	union sockaddr_union so;
	socklen_t addrlen = sizeof(so);
	char hbuf[NI_MAXHOST];
	int ret;

	i_zero(&so);
	sin_set_ip(&so, ip);
	ret = getnameinfo(&so.sa, addrlen, hbuf, sizeof(hbuf), NULL, 0,
			  NI_NAMEREQD);
	if (ret != 0)
		return ret;

	*name_r = t_strdup(hbuf);
	return 0;
}

int net_getsockname(int fd, struct ip_addr *addr, in_port_t *port)
{
	union sockaddr_union so;
	socklen_t addrlen;

	i_assert(fd >= 0);

	i_zero(&so);
	addrlen = sizeof(so);
	if (getsockname(fd, &so.sa, &addrlen) == -1)
		return -1;
	if (so.sin.sin_family == AF_UNIX) {
		if (addr != NULL)
			i_zero(addr);
		if (port != NULL) *port = 0;
	} else {
		if (addr != NULL) sin_get_ip(&so, addr);
		if (port != NULL) *port = sin_get_port(&so);
	}
	return 0;
}

int net_getpeername(int fd, struct ip_addr *addr, in_port_t *port)
{
	union sockaddr_union so;
	socklen_t addrlen;

	i_assert(fd >= 0);

	i_zero(&so);
	addrlen = sizeof(so);
	if (getpeername(fd, &so.sa, &addrlen) == -1)
		return -1;
	if (so.sin.sin_family == AF_UNIX) {
		if (addr != NULL)
			i_zero(addr);
		if (port != NULL) *port = 0;
	} else {
		if (addr != NULL) sin_get_ip(&so, addr);
		if (port != NULL) *port = sin_get_port(&so);
	}
	return 0;
}

int net_getunixname(int fd, const char **name_r)
{
	union sockaddr_union_unix so;
	socklen_t addrlen = sizeof(so);

	i_zero(&so);
	if (getsockname(fd, &so.sa, &addrlen) < 0)
		return -1;
	if (so.un.sun_family != AF_UNIX) {
		errno = ENOTSOCK;
		return -1;
	}
	*name_r = t_strdup(so.un.sun_path);
	return 0;
}

int net_getunixcred(int fd, struct net_unix_cred *cred_r)
{
#if defined(SO_PEERCRED)
# if defined(HAVE_STRUCT_SOCKPEERCRED)
	/* OpenBSD (may also provide getpeereid, but we also want pid) */
	struct sockpeercred ucred;
# else
	/* Linux */
	struct ucred ucred;
# endif
	socklen_t len = sizeof(ucred);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) < 0) {
		i_error("getsockopt(SO_PEERCRED) failed: %m");
		return -1;
	}
	cred_r->uid = ucred.uid;
	cred_r->gid = ucred.gid;
	cred_r->pid = ucred.pid;
	return 0;
#elif defined(LOCAL_PEEREID)
	/* NetBSD (may also provide getpeereid, but we also want pid) */
	struct unpcbid ucred;
	socklen_t len = sizeof(ucred);

	if (getsockopt(fd, 0, LOCAL_PEEREID, &ucred, &len) < 0) {
		i_error("getsockopt(LOCAL_PEEREID) failed: %m");
		return -1;
	}
	
	cred_r->uid = ucred.unp_euid;
	cred_r->gid = ucred.unp_egid;
	cred_r->pid = ucred.unp_pid;
	return 0;
#elif defined(HAVE_GETPEEREID)
	/* OSX 10.4+, FreeBSD 4.6+, OpenBSD 3.0+, NetBSD 5.0+ */
	if (getpeereid(fd, &cred_r->uid, &cred_r->gid) < 0) {
		i_error("getpeereid() failed: %m");
		return -1;
	}
	cred_r->pid = (pid_t)-1;
	return 0;
#elif defined(LOCAL_PEERCRED)
	/* Older FreeBSD */
	struct xucred ucred;
	socklen_t len = sizeof(ucred);

	if (getsockopt(fd, 0, LOCAL_PEERCRED, &ucred, &len) < 0) {
		i_error("getsockopt(LOCAL_PEERCRED) failed: %m");
		return -1;
	}

	if (ucred.cr_version != XUCRED_VERSION) {
		errno = EINVAL;
		return -1;
	}

	cred_r->uid = ucred.cr_uid;
	cred_r->gid = ucred.cr_gid;
	cred_r->pid = (pid_t)-1;
	return 0;
#elif defined(HAVE_GETPEERUCRED)
	/* Solaris */
	ucred_t *ucred = NULL;

	if (getpeerucred(fd, &ucred) < 0) {
		i_error("getpeerucred() failed: %m");
		return -1;
	}
	cred_r->uid = ucred_geteuid(ucred);
	cred_r->gid = ucred_getrgid(ucred);
	cred_r->pid = ucred_getpid(ucred);
	ucred_free(ucred);

	if (cred_r->uid == (uid_t)-1 ||
	    cred_r->gid == (gid_t)-1) {
		errno = EINVAL;
		return -1;
	}
	return 0;
#elif defined(NEEDS_LOCAL_CREDS)
	/* NetBSD < 5 */
	int i, n, on;
	struct iovec iov;
	struct msghdr msg;
	struct {
		struct cmsghdr ch;
		char buf[110];
	} cdata;
	struct sockcred *sc;

	iov.iov_base = (char *)&on;
	iov.iov_len = 1;

	sc = (struct sockcred *)cdata.buf;
	sc->sc_uid = sc->sc_euid = sc->sc_gid = sc->sc_egid = -1;
	i_zero(&cdata.ch);

	i_zero(&msg);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cdata;
	msg.msg_controllen = sizeof(cdata.ch) + sizeof(cdata.buf);

	for (i = 0; i < 10; i++) {
		n = recvmsg(fd, &msg, MSG_WAITALL | MSG_PEEK);
		if (n >= 0 || errno != EAGAIN)
			break;
		usleep(100);
	}
	if (n < 0) {
		i_error("recvmsg() failed: %m");
		return -1;
	}
	cred_r->uid = sc->sc_euid;
	cred_r->gid = sc->sc_egid;
	cred_r->pid = (pid_t)-1;
	return 0;
#else
	errno = EINVAL;
	return -1;
#endif
}

const char *net_ip2addr(const struct ip_addr *ip)
{
	char *addr = t_malloc_no0(MAX_IP_LEN+1);

	if (inet_ntop(ip->family, &ip->u.ip6, addr, MAX_IP_LEN) == NULL)
		return "";

	return addr;
}

static bool net_addr2ip_inet4_fast(const char *addr, struct ip_addr *ip)
{
	uint8_t *saddr = (void *)&ip->u.ip4.s_addr;
	unsigned int i, num;

	if (str_parse_uint(addr, &num, &addr) < 0)
		return FALSE;
	if (*addr == '\0' && num <= 0xffffffff) {
		/* single-number IPv4 address */
		ip->u.ip4.s_addr = htonl(num);
		ip->family = AF_INET;
		return TRUE;
	}

	/* try to parse as a.b.c.d */
	i = 0;
	for (;;) {
		if (num >= 256)
			return FALSE;
		saddr[i] = num;
		if (i == 3)
			break;
		i++;
		if (*addr != '.')
			return FALSE;
		addr++;
		if (str_parse_uint(addr, &num, &addr) < 0)
			return FALSE;
	}
	if (*addr != '\0')
		return FALSE;
	ip->family = AF_INET;
	return TRUE;
}

int net_addr2ip(const char *addr, struct ip_addr *ip)
{
	int ret;

	if (net_addr2ip_inet4_fast(addr, ip))
		return 0;

	if (strchr(addr, ':') != NULL) {
		/* IPv6 */
		T_BEGIN {
			if (addr[0] == '[') {
				/* allow [ipv6 addr] */
				size_t len = strlen(addr);
				if (addr[len-1] == ']')
					addr = t_strndup(addr+1, len-2);
			}
			ret = inet_pton(AF_INET6, addr, &ip->u.ip6);
		} T_END;
		if (ret == 0)
			return -1;
		ip->family = AF_INET6;
 	} else {
		/* IPv4 */
		if (inet_aton(addr, &ip->u.ip4) == 0)
			return -1;
		ip->family = AF_INET;
	}
	return 0;
}

int net_str2port(const char *str, in_port_t *port_r)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return -1;

	if (l == 0 || l > (in_port_t)-1)
		return -1;
	*port_r = (in_port_t)l;
	return 0;
}

int net_str2port_zero(const char *str, in_port_t *port_r)
{
	uintmax_t l;

	if (str_to_uintmax(str, &l) < 0)
		return -1;

	if (l > (in_port_t)-1)
		return -1;
	*port_r = (in_port_t)l;
	return 0;
}

int net_str2hostport(const char *str, in_port_t default_port,
		     const char **host_r, in_port_t *port_r)
{
	const char *p, *host;
	in_port_t port;

	if (str[0] == '[') {
		/* [IPv6] address, possibly followed by :port */
		p = strchr(str, ']');
		if (p == NULL)
			return -1;
		host = t_strdup_until(str+1, p++);
	} else {
		p = strchr(str, ':');
		if (p == NULL || strchr(p+1, ':') != NULL) {
			/* host or IPv6 address */
			*host_r = str;
			*port_r = default_port;
			return 0;
		}
		host = t_strdup_until(str, p);
	}
	if (p[0] == '\0') {
		*host_r = host;
		*port_r = default_port;
		return 0;
	}
	if (p[0] != ':')
		return -1;
	if (net_str2port(p+1, &port) < 0)
		return -1;
	*host_r = host;
	*port_r = port;
	return 0;
}

int net_ipport2str(const struct ip_addr *ip, in_port_t port, const char **str_r)
{
	if (!IPADDR_IS_V4(ip) && !IPADDR_IS_V6(ip)) return -1;

	*str_r = t_strdup_printf("%s%s%s:%u",
				 IPADDR_IS_V6(ip) ? "[" : "",
				 net_ip2addr(ip),
				 IPADDR_IS_V6(ip) ? "]" : "",
				 port);
	return 0;
}

int net_ipv6_mapped_ipv4_convert(const struct ip_addr *src,
				 struct ip_addr *dest)
{
	static uint8_t v4_prefix[] =
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

	if (!IPADDR_IS_V6(src))
		return -1;
	if (memcmp(src->u.ip6.s6_addr, v4_prefix, sizeof(v4_prefix)) != 0)
		return -1;

	i_zero(dest);
	dest->family = AF_INET;
	memcpy(&dest->u.ip6, &src->u.ip6.s6_addr[3*4], 4);
	return 0;
}

int net_geterror(int fd)
{
	int data;
	socklen_t len = sizeof(data);

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &data, &len) == -1) {
		/* we're now really returning the getsockopt()'s error code
		   instead of the socket's, but normally we should never get
		   here anyway. */
		return errno;
	}

	return data;
}

const char *net_gethosterror(int error)
{
	i_assert(error != 0);

	return gai_strerror(error);
}

enum net_hosterror_type net_get_hosterror_type(int error)
{
	const struct {
		int error;
		enum net_hosterror_type type;
	} error_map[] = {
		{ EAI_ADDRFAMILY, NET_HOSTERROR_TYPE_NOT_FOUND },
		{ EAI_AGAIN, NET_HOSTERROR_TYPE_NAMESERVER },
		{ EAI_BADFLAGS, NET_HOSTERROR_TYPE_INTERNAL_ERROR },
		{ EAI_FAIL, NET_HOSTERROR_TYPE_NAMESERVER },
		{ EAI_FAMILY, NET_HOSTERROR_TYPE_INTERNAL_ERROR },
		{ EAI_MEMORY, NET_HOSTERROR_TYPE_INTERNAL_ERROR },
		{ EAI_NODATA, NET_HOSTERROR_TYPE_NOT_FOUND },
		{ EAI_NONAME, NET_HOSTERROR_TYPE_NOT_FOUND },
		{ EAI_SERVICE, NET_HOSTERROR_TYPE_INTERNAL_ERROR },
		{ EAI_SOCKTYPE, NET_HOSTERROR_TYPE_INTERNAL_ERROR },
		{ EAI_SYSTEM, NET_HOSTERROR_TYPE_INTERNAL_ERROR },
	};
	for (unsigned int i = 0; i < N_ELEMENTS(error_map); i++) {
		if (error_map[i].error == error)
			return error_map[i].type;
	}

	/* shouldn't happen? assume internal error */
	return NET_HOSTERROR_TYPE_INTERNAL_ERROR;
}

int net_hosterror_notfound(int error)
{
#ifdef EAI_NODATA /* NODATA is depricated */
	return (error != 1 && (error == EAI_NONAME || error == EAI_NODATA)) ? 1 : 0;
#else
	return (error != 1 && (error == EAI_NONAME)) ? 1 : 0;
#endif
}

const char *net_getservbyport(in_port_t port)
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

	max_bits = IPADDR_BITS(ip_r);
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

	if (ip->family == 0 || net_ip->family == 0) {
		/* non-IPv4/IPv6 address (e.g. UNIX socket) never matches
		   anything */
		return FALSE;
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
		ip1 = (const void *)&ip->u.ip6;
		ip2 = (const void *)&net_ip->u.ip6;
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
