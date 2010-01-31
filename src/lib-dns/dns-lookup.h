#ifndef DNS_LOOKUP_H
#define DNS_LOOKUP_H

struct dns_lookup_settings {
	const char *dns_client_socket_path;
	unsigned int timeout_msecs;
};

struct dns_lookup_result {
	/* all is ok if ret=0, otherwise it contains net_gethosterror()
	   compatible error code. error string is always set if ret != 0. */
	int ret;
	const char *error;

	/* how many milliseconds the lookup took. */
	unsigned int msecs;

	unsigned int ips_count;
	const struct ip_addr *ips;
};

typedef void dns_lookup_callback_t(const struct dns_lookup_result *result,
				   void *context);

int dns_lookup(const char *host, const struct dns_lookup_settings *set,
	       dns_lookup_callback_t *callback, void *context);
#define dns_lookup(host, set, callback, context) \
	CONTEXT_CALLBACK2(dns_lookup, dns_lookup_callback_t, \
			  callback, const struct dns_lookup_result *, \
			  context, host, set)

#endif
