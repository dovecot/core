#ifndef __NETWORK_H
#define __NETWORK_H

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

struct _IPADDR {
	unsigned short family;
#ifdef HAVE_IPV6
	struct in6_addr ip;
#else
	struct in_addr ip;
#endif
};

/* maxmimum string length of IP address */
#ifdef HAVE_IPV6
#  define MAX_IP_LEN INET6_ADDRSTRLEN
#else
#  define MAX_IP_LEN 20
#endif

#define IPADDR_IS_V4(ip) ((ip)->family == AF_INET)
#define IPADDR_IS_V6(ip) ((ip)->family == AF_INET6)

/* returns 1 if IPADDRs are the same */
int net_ip_compare(const IPADDR *ip1, const IPADDR *ip2);

/* Connect to socket with ip address */
int net_connect_ip(const IPADDR *ip, unsigned int port, const IPADDR *my_ip);
/* Connect to named UNIX socket */
int net_connect_unix(const char *path);
/* Disconnect socket */
void net_disconnect(int fd);
/* Try to let the other side close the connection, if it still isn't
   disconnected after certain amount of time, close it ourself */
void net_disconnect_later(int fd);

/* Set socket blocking/nonblocking */
void net_set_nonblock(int fd, int nonblock);
/* Set TCP_CORK if supported, ie. don't send out partial frames.
   Returns 0 if ok, -1 if failed. */
int net_set_cork(int fd, int cork);

/* Set IP to contain INADDR_ANY for IPv4 or IPv6. The IPv6 any address may
   include IPv4 depending on the system (Linux yes, BSD no). */
void net_get_ip_any4(IPADDR *ip);
void net_get_ip_any6(IPADDR *ip);

/* Listen for connections on a socket */
int net_listen(const IPADDR *my_ip, unsigned int *port);
/* Listen for connections on an UNIX socket */
int net_listen_unix(const char *path);
/* Accept a connection on a socket. Returns -1 for temporary failure,
   -2 for fatal failure */
int net_accept(int fd, IPADDR *addr, unsigned int *port);

/* Read data from socket, return number of bytes read, -1 = error */
ssize_t net_receive(int fd, void *buf, size_t len);
/* Transmit data, return number of bytes sent, -1 = error */
ssize_t net_transmit(int fd, const void *data, size_t len);

/* Get IP addresses for host. ips contains ips_count of IPs, they don't need
   to be free'd. Returns 0 = ok, others = error code for net_gethosterror() */
int net_gethostbyname(const char *addr, IPADDR **ips, int *ips_count);
/* get error of net_gethostname() */
const char *net_gethosterror(int error);
/* return TRUE if host lookup failed because it didn't exist (ie. not
   some error with name server) */
int net_hosterror_notfound(int error);

/* Get socket address/port */
int net_getsockname(int fd, IPADDR *addr, unsigned int *port);

/* IPADDR -> char* translation. `host' must be at least MAX_IP_LEN bytes */
int net_ip2host(const IPADDR *ip, char *host);
/* char* -> IPADDR translation. */
int net_host2ip(const char *host, IPADDR *ip);

/* Get socket error */
int net_geterror(int fd);

/* Get name of TCP service */
char *net_getservbyport(unsigned short port);

int is_ipv4_address(const char *host);
int is_ipv6_address(const char *host);

#endif
