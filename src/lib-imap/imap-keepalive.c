/* Copyright (c) 2002-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "crc32.h"
#include "net.h"
#include "imap-keepalive.h"

#include <time.h>

static bool imap_remote_ip_is_usable(const struct ip_addr *ip)
{
	unsigned int addr;

	if (ip->family == 0)
		return FALSE;
	if (ip->family == AF_INET) {
#define IP4(a,b,c,d) ((unsigned)(a)<<24|(unsigned)(b)<<16|(unsigned)(c)<<8|(unsigned)(d))
		addr = ip->u.ip4.s_addr;
		if (addr >= IP4(10,0,0,0) && addr <= IP4(10,255,255,255))
			return FALSE; /* 10/8 */
		if (addr >= IP4(192,168,0,0) && addr <= IP4(192,168,255,255))
			return FALSE; /* 192.168/16 */
		if (addr >= IP4(172,16,0,0) && addr <= IP4(172,31,255,255))
			return FALSE; /* 172.16/12 */
		if (addr >= IP4(127,0,0,0) && addr <= IP4(127,255,255,255))
			return FALSE; /* 127/8 */
#undef IP4
	}
	else if (ip->family == AF_INET6) {
		addr = ip->u.ip6.s6_addr[0];
		if (addr == 0xfc || addr == 0xfd)
			return FALSE; /* fc00::/7 */
	}
	return TRUE;
}

unsigned int
imap_keepalive_interval_msecs(const char *username, const struct ip_addr *ip,
			      unsigned int interval_secs)
{
	unsigned int client_hash;

	client_hash = ip != NULL && imap_remote_ip_is_usable(ip) ?
		net_ip_hash(ip) : crc32_str(username);
	interval_secs -= (time(NULL) + client_hash) % interval_secs;
	return interval_secs * 1000;
}
