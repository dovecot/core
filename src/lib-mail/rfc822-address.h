#ifndef __RFC822_ADDRLIST_H
#define __RFC822_ADDRLIST_H

typedef struct _Rfc822Address Rfc822Address;

struct _Rfc822Address {
	Rfc822Address *next;

	char *name, *route, *mailbox, *domain;
};

Rfc822Address *rfc822_address_parse(Pool pool, const unsigned char *data,
				    size_t size);

#endif
