#ifndef NET_H
#define NET_H

#ifndef WIN32
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netdb.h>
#  include <arpa/inet.h>
#endif

#ifdef HAVE_SOCKS_H
#include <socks.h>
#endif

#ifndef AF_INET6
#  ifdef PF_INET6
#    define AF_INET6 PF_INET6
#  else
#    define AF_INET6 10
#  endif
#endif

struct ip_addr {
	unsigned short family;
	union {
		struct in6_addr ip6;
		struct in_addr ip4;
	} u;
};
ARRAY_DEFINE_TYPE(ip_addr, struct ip_addr);

struct net_unix_cred {
	uid_t uid;
	gid_t gid;
	pid_t pid;
};

/* maximum string length of IP address */
#define MAX_IP_LEN INET6_ADDRSTRLEN

#define IPADDR_IS_V4(ip) ((ip)->family == AF_INET)
#define IPADDR_IS_V6(ip) ((ip)->family == AF_INET6)
#define IPADDR_BITS(ip) (IPADDR_IS_V4(ip) ? 32 : 128)

enum net_listen_flags {
	/* Try to use SO_REUSEPORT if available. If it's not, this flag is
	   cleared on return. */
	NET_LISTEN_FLAG_REUSEPORT	= 0x01
};

enum net_hosterror_type {
	/* Internal error - should be logged as an error */
	NET_HOSTERROR_TYPE_INTERNAL_ERROR,
	/* Host not found or no valid IP addresses found */
	NET_HOSTERROR_TYPE_NOT_FOUND,
	/* Nameserver returned an error */
	NET_HOSTERROR_TYPE_NAMESERVER,
};

/* INADDR_ANY for IPv4 or IPv6. The IPv6 any address may
   include IPv4 depending on the system (Linux yes, BSD no). */
extern const struct ip_addr net_ip4_any;
extern const struct ip_addr net_ip6_any;

extern const struct ip_addr net_ip4_loopback;
extern const struct ip_addr net_ip6_loopback;

/* Returns TRUE if IPs are the same */
bool net_ip_compare(const struct ip_addr *ip1, const struct ip_addr *ip2);
/* Returns 0 if IPs are the same, -1 or 1 otherwise. */
int net_ip_cmp(const struct ip_addr *ip1, const struct ip_addr *ip2);
unsigned int net_ip_hash(const struct ip_addr *ip);

/* Connect to TCP socket with ip address. The socket and connect() is
   non-blocking. */
int net_connect_ip(const struct ip_addr *ip, in_port_t port,
		   const struct ip_addr *my_ip) ATTR_NULL(3);
/* Like net_connect_ip(), but do a blocking connect(). */
int net_connect_ip_blocking(const struct ip_addr *ip, in_port_t port,
			    const struct ip_addr *my_ip) ATTR_NULL(3);
/* Like net_connect_ip(), but open a UDP socket. */ 
int net_connect_udp(const struct ip_addr *ip, in_port_t port,
		    const struct ip_addr *my_ip);
/* Returns 0 if we can bind() as given IP, -1 if not. */
int net_try_bind(const struct ip_addr *ip);
/* Connect to named UNIX socket */
int net_connect_unix(const char *path);
/* Try to connect to UNIX socket for give number of seconds when connect()
   returns EAGAIN or ECONNREFUSED. */
int net_connect_unix_with_retries(const char *path, unsigned int msecs);
/* Disconnect socket */
void net_disconnect(int fd);

/* Set socket blocking/nonblocking */
void net_set_nonblock(int fd, bool nonblock);
/* Set TCP_CORK if supported, ie. don't send out partial frames.
   Returns 0 if ok, -1 if failed. */
int net_set_cork(int fd, bool cork) ATTR_NOWARN_UNUSED_RESULT;
/* Set TCP_NODELAY, which disables the Nagle algorithm. */
int net_set_tcp_nodelay(int fd, bool nodelay);

/* Set socket kernel buffer sizes */
int net_set_send_buffer_size(int fd, size_t size);
int net_set_recv_buffer_size(int fd, size_t size);

/* Listen for connections on a socket */
int net_listen(const struct ip_addr *my_ip, in_port_t *port, int backlog);
int net_listen_full(const struct ip_addr *my_ip, in_port_t *port,
		    enum net_listen_flags *flags, int backlog);
/* Listen for connections on an UNIX socket */
int net_listen_unix(const char *path, int backlog);
/* Like net_listen_unix(), but if socket already exists, try to connect to it.
   If it fails with ECONNREFUSED, unlink the socket and try creating it
   again. */
int net_listen_unix_unlink_stale(const char *path, int backlog);
/* Accept a connection on a socket. Returns -1 if the connection got closed,
   -2 for other failures. For UNIX sockets addr_r->family=port=0. */
int net_accept(int fd, struct ip_addr *addr_r, in_port_t *port_r)
	ATTR_NULL(2, 3);

/* Read data from socket, return number of bytes read,
   -1 = error, -2 = disconnected */
ssize_t net_receive(int fd, void *buf, size_t len);

/* Get IP addresses for host. ips contains ips_count of IPs, they don't need
   to be free'd. Returns 0 = ok, others = error code for net_gethosterror() */
int net_gethostbyname(const char *addr, struct ip_addr **ips,
		      unsigned int *ips_count);
/* Return host for the IP address. Returns 0 = ok, others = error code for
   net_gethosterror(). */
int net_gethostbyaddr(const struct ip_addr *ip, const char **name_r);
/* get error of net_gethostname() */
const char *net_gethosterror(int error) ATTR_CONST;
/* Return type of the error returned by net_gethostname() */
enum net_hosterror_type net_get_hosterror_type(int error);
/* return TRUE if host lookup failed because it didn't exist (ie. not
   some error with name server) */
int net_hosterror_notfound(int error) ATTR_CONST;

/* Get socket local address/port. For UNIX sockets addr->family=port=0. */
int net_getsockname(int fd, struct ip_addr *addr, in_port_t *port)
	ATTR_NULL(2, 3);
/* Get socket remote address/port. For UNIX sockets addr->family=port=0. */
int net_getpeername(int fd, struct ip_addr *addr, in_port_t *port)
	ATTR_NULL(2, 3);
/* Get UNIX socket name. */
int net_getunixname(int fd, const char **name_r);
/* Get UNIX socket peer process's credentials. The pid may be (pid_t)-1 if
   unavailable. */
int net_getunixcred(int fd, struct net_unix_cred *cred_r);

/* Returns ip_addr as string, or "" if ip isn't valid IPv4 or IPv6 address. */
const char *net_ip2addr(const struct ip_addr *ip);
/* char* -> struct ip_addr translation. */
int net_addr2ip(const char *addr, struct ip_addr *ip);
/* char* -> in_port_t translation */
int net_str2port(const char *str, in_port_t *port_r);
/* char* -> in_port_t translation (allows port zero) */
int net_str2port_zero(const char *str, in_port_t *port_r);
/* Parse "host", "host:port", "IPv4", "IPv4:port", "IPv6", "[IPv6]" or
   "[IPv6]:port" to its host and port components. [IPv6] address is returned
   without []. If no port is given, return default_port. The :port in the
   parsed string isn't allowed to be zero, but default_port=0 is passed
   through. */
int net_str2hostport(const char *str, in_port_t default_port,
		     const char **host_r, in_port_t *port_r);
/* Converts ip and port to ipv4:port or [ipv6]:port. Returns -1 if
   ip is not valid IPv4 or IPv6 address. */
int net_ipport2str(const struct ip_addr *ip, in_port_t port, const char **str_r);

/* Convert IPv6 mapped IPv4 address to an actual IPv4 address. Returns 0 if
   successful, -1 if the source address isn't IPv6 mapped IPv4 address. */
int net_ipv6_mapped_ipv4_convert(const struct ip_addr *src,
				 struct ip_addr *dest);

/* Get socket error */
int net_geterror(int fd);

/* Get name of TCP service */
const char *net_getservbyport(in_port_t port) ATTR_CONST;

bool is_ipv4_address(const char *addr) ATTR_PURE;
bool is_ipv6_address(const char *addr) ATTR_PURE;

/* Parse network as ip/bits. Returns 0 if successful, -1 if invalid input. */
int net_parse_range(const char *network, struct ip_addr *ip_r,
		    unsigned int *bits_r);
/* Returns TRUE if ip is in net_ip/bits network. IPv4-mapped IPv6 addresses
   in "ip" parameter are converted to plain IPv4 addresses before matching.
   No conversion is done to net_ip though, so using IPv4-mapped IPv6 addresses
   there will always fail. Invalid IPs (family=0) never match anything. */
bool net_is_in_network(const struct ip_addr *ip, const struct ip_addr *net_ip,
		       unsigned int bits) ATTR_PURE;

#endif
