#ifndef DNS_LOOKUP_H
#define DNS_LOOKUP_H

#define DNS_CLIENT_SOCKET_NAME "dns-client"

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

	/* for IP lookup: */
	unsigned int ips_count;
	const struct ip_addr *ips;
	/* for PTR lookup: */
	const char *name;
};

typedef void dns_lookup_callback_t(const struct dns_lookup_result *result,
				   void *context);

/* Do asynchronous DNS lookup via dns-client UNIX socket. Returns 0 if lookup
   started, -1 if there was an error communicating with the UNIX socket.
   When failing with -1, the callback is called before returning from the
   function. */
int dns_lookup(const char *host, const struct dns_lookup_settings *set,
	       dns_lookup_callback_t *callback, void *context,
	       struct dns_lookup **lookup_r) ATTR_NULL(4);
#define dns_lookup(host, set, callback, context, lookup_r) \
	dns_lookup(host + \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct dns_lookup_result *, typeof(context))), \
		set, (dns_lookup_callback_t *)callback, context, lookup_r)
int dns_lookup_ptr(const struct ip_addr *ip,
		   const struct dns_lookup_settings *set,
		   dns_lookup_callback_t *callback, void *context,
		   struct dns_lookup **lookup_r) ATTR_NULL(4);
#define dns_lookup_ptr(host, set, callback, context, lookup_r) \
	dns_lookup_ptr(host + \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const struct dns_lookup_result *, typeof(context))), \
		set, (dns_lookup_callback_t *)callback, context, lookup_r)
/* Abort the DNS lookup without calling the callback. */
void dns_lookup_abort(struct dns_lookup **lookup);

void dns_lookup_switch_ioloop(struct dns_lookup *lookup);

#endif
