/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "director.h"
#include "director-host.h"

static int director_host_cmp(const struct director_host *b1,
			     const struct director_host *b2)
{
	int ret;

	ret = net_ip_cmp(&b1->ip, &b2->ip);
	if (ret != 0)
		return ret;
	return (int)b1->port - (int)b2->port;
}

int director_host_cmp_p(struct director_host *const *host1,
			struct director_host *const *host2)
{
	return director_host_cmp(*host1, *host2);
}

struct director_host *
director_host_add(struct director *dir,
		  const struct ip_addr *ip, in_port_t port)
{
	struct director_host *host;

	i_assert(director_host_lookup(dir, ip, port) == NULL);

	host = i_new(struct director_host, 1);
	host->dir = dir;
	host->refcount = 1;
	host->ip = *ip;
	host->ip_str = i_strdup(net_ip2addr(&host->ip));
	host->port = port;
	host->name = i_strdup_printf("%s:%u", host->ip_str, port);

	array_push_back(&dir->dir_hosts, &host);

	/* there are few enough directors that sorting after each
	   addition should be fine */
	array_sort(&dir->dir_hosts, director_host_cmp_p);
	return host;
}

void director_host_free(struct director_host **_host)
{
	struct director_host *host = *_host;

	i_assert(host->refcount == 1);

	*_host = NULL;
	director_host_unref(host);
}

void director_host_ref(struct director_host *host)
{
	i_assert(host->refcount > 0);
	host->refcount++;
}

void director_host_unref(struct director_host *host)
{
	struct director_host *const *hosts;
	unsigned int i, count;

	i_assert(host->refcount > 0);

	if (--host->refcount > 0)
		return;

	hosts = array_get(&host->dir->dir_hosts, &count);
	for (i = 0; i < count; i++) {
		if (hosts[i] == host) {
			array_delete(&host->dir->dir_hosts, i, 1);
			break;
		}
	}
	i_free(host->name);
	i_free(host->ip_str);
	i_free(host);
}

void director_host_restarted(struct director_host *host)
{
	host->last_seq = 0;
	host->last_sync_seq = 0;
	host->last_sync_seq_counter = 0;
	host->last_sync_timestamp = 0;
}

struct director_host *
director_host_get(struct director *dir, const struct ip_addr *ip,
		  in_port_t port)
{
	struct director_host *host;

	host = director_host_lookup(dir, ip, port);
	if (host == NULL)
		host = director_host_add(dir, ip, port);
	return host;
}

struct director_host *
director_host_lookup(struct director *dir, const struct ip_addr *ip,
		     in_port_t port)
{
	struct director_host *const *hostp;

	array_foreach(&dir->dir_hosts, hostp) {
		if (net_ip_compare(&(*hostp)->ip, ip) &&
		    (*hostp)->port == port)
			return *hostp;
	}
	return NULL;
}

struct director_host *
director_host_lookup_ip(struct director *dir, const struct ip_addr *ip)
{
	struct director_host *const *hostp;

	array_foreach(&dir->dir_hosts, hostp) {
		if (net_ip_compare(&(*hostp)->ip, ip))
			return *hostp;
	}
	return NULL;
}

int director_host_cmp_to_self(const struct director_host *b1,
			      const struct director_host *b2,
			      const struct director_host *self)
{
	int ret;

	if ((ret = director_host_cmp(b1, b2)) >= 0)
		return ret == 0 ? 0 : -director_host_cmp_to_self(b2, b1, self);

	/* order -> return:
	   self, b1, b2 -> b2
	   b1, self, b2 -> b1
	   b1, b2, self -> b2
	*/
	if (director_host_cmp(self, b1) < 0)
		return 1; /* self, b1, b2 */
	if (director_host_cmp(self, b2) < 0)
		return -1; /* b1, self, b2 */
	return 1; /* b1, b2, self */
}

static void director_host_add_string(struct director *dir, const char *host)
{
	struct ip_addr *ips;
	in_port_t port;
	unsigned int i, ips_count;

	if (net_str2hostport(host, dir->self_port, &host, &port) < 0)
		i_fatal("Invalid director host:port in '%s'", host);

	if (net_gethostbyname(host, &ips, &ips_count) < 0)
		i_fatal("Unknown director host: %s", host);

	for (i = 0; i < ips_count; i++) {
		if (director_host_lookup(dir, &ips[i], port) == NULL)
			(void)director_host_add(dir, &ips[i], port);
	}
}

void director_host_add_from_string(struct director *dir, const char *hosts)
{
	T_BEGIN {
		const char *const *tmp;

		tmp = t_strsplit_spaces(hosts, " ");
		for (; *tmp != NULL; tmp++)
			director_host_add_string(dir, *tmp);
	} T_END;

	if (array_count(&dir->dir_hosts) == 0) {
		/* standalone director */
		struct ip_addr ip;

		if (net_addr2ip("127.0.0.1", &ip) < 0)
			i_unreached();
		dir->self_host = director_host_add(dir, &ip, 0);
		dir->self_host->self = TRUE;
	}
}
