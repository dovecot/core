#ifndef DNS_LOOKUP_H
#define DNS_LOOKUP_H

struct dns_lookup;

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

/* Do asynchronous DNS lookup via dns-client UNIX socket. Returns 0 if lookup
   started, -1 if there was an error communicating with the UNIX socket.
   When failing with -1, the callback is called before returning from the
   function. */
int dns_lookup(const char *host, const struct dns_lookup_settings *set,
	       struct dns_lookup **lookup_r,
	       dns_lookup_callback_t *callback, void *context) ATTR_NULL(5);
#define dns_lookup(host, set, callback, context, lookup_r) \
	CONTEXT_CALLBACK2(dns_lookup, dns_lookup_callback_t, \
			  callback, const struct dns_lookup_result *, \
			  context, host, set, lookup_r)
/* Abort the DNS lookup without calling the callback. */
void dns_lookup_abort(struct dns_lookup **lookup);

#endif
