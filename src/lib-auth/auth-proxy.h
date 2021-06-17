#ifndef AUTH_PROXY_H
#define AUTH_PROXY_H

#include "net.h"

enum auth_proxy_ssl_flags {
	/* Use SSL/TLS */
	AUTH_PROXY_SSL_FLAG_YES		= BIT(0),
	/* Don't do SSL handshake immediately after connected */
	AUTH_PROXY_SSL_FLAG_STARTTLS	= BIT(1),
	/* Don't require that the received certificate is valid */
	AUTH_PROXY_SSL_FLAG_ANY_CERT	= BIT(2),
};

struct auth_proxy_settings {
	/* TRUE if proxying is enabled */
	bool proxy;

	/* Destination hostname or IP */
	const char *host;
	/* Destination IP address, parsed from "hostip" or "host" field */
	struct ip_addr host_ip;
	/* Destination port */
	in_port_t port;
	/* SSL connection options */
	enum auth_proxy_ssl_flags ssl_flags;

	/* If family != 0, source IP address to use for the outgoing
	   connection. */
	struct ip_addr source_ip;

	/* Login user/master/password */
	const char *username;
	const char *master_user;
	const char *password;
	/* SASL mechanism to use for authentication. */
	const char *sasl_mechanism;

	/* Abort proxy connection in this many milliseconds (0 = default) */
	unsigned int timeout_msecs;

	/* Disable pipelining commands to destination server */
	bool nopipelining:1;
	/* Submission service: Disable logging into the destination server.
	   Use XCLIENT LOGIN instead. */
	bool noauth:1;
	/* Remote server isn't trusted - don't use any ID/XCLIENT extensions
	   to send the original client information. */
	bool remote_not_trusted:1;
	/* If redirect/referral is received, do another PASS lookup instead of
	   directly connecting to the redirected host. */
	bool redirect_reauth:1;
};

/* Apply key/value into auth_proxy_settings. Returns 1 if successful, 0 if
   key isn't a proxy setting, -1 if the value was invalid. If pool is NULL,
   values are directly stored to settings. */
int auth_proxy_settings_parse(struct auth_proxy_settings *set, pool_t pool,
			      const char *key, const char *value,
			      const char **error_r);

/* Parse [user@]ip[:port] string. Note that host must currently always be IP. */
bool auth_proxy_parse_redirect(const char *target,
			       const char **destuser_r,
			       const char **host_r, struct ip_addr *ip_r,
			       in_port_t *port_r);

#endif
