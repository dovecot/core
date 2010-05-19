/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-host.h"

#define VHOST_MULTIPLIER 100

static ARRAY_TYPE(mail_host) hosts;
static ARRAY_DEFINE(vhosts, struct mail_host *);
static bool hosts_unsorted;

static int
mail_host_cmp(struct mail_host *const *h1, struct mail_host *const *h2)
{
	return net_ip_cmp(&(*h1)->ip, &(*h2)->ip);
}

static void mail_hosts_sort(void)
{
	struct mail_host *const *hostp;
	unsigned int i;

	array_sort(&hosts, mail_host_cmp);

	/* rebuild vhosts */
	array_clear(&vhosts);
	array_foreach(&hosts, hostp) {
		for (i = 0; i < (*hostp)->vhost_count; i++)
			array_append(&vhosts, hostp, 1);
	}
	hosts_unsorted = FALSE;
}

struct mail_host *mail_host_add_ip(const struct ip_addr *ip)
{
	struct mail_host *host;

	host = i_new(struct mail_host, 1);
	host->vhost_count = VHOST_MULTIPLIER;
	host->ip = *ip;
	array_append(&hosts, &host, 1);

	hosts_unsorted = TRUE;
	return host;
}

static int mail_host_add(const char *host)
{
	struct ip_addr ip;

	if (net_addr2ip(host, &ip) < 0) {
		i_error("Invalid IP address: %s", host);
		return -1;
	}

	mail_host_add_ip(&ip);
	return 0;
}

static int mail_hosts_add_range(const char *host1, const char *host2)
{
	struct ip_addr ip1, ip2;

	if (net_addr2ip(host1, &ip1) < 0) {
		i_error("Invalid IP address: %s", host1);
		return -1;
	}
	if (net_addr2ip(host2, &ip2) < 0) {
		i_error("Invalid IP address: %s", host2);
		return -1;
	}

	// FIXME

	return 0;
}

int mail_hosts_parse_and_add(const char *hosts_list)
{
	int ret = 0;

	T_BEGIN {
		const char *const *tmp, *p;

		tmp = t_strsplit_spaces(hosts_list, " ");
		for (; *tmp != NULL; tmp++) {
			p = strchr(*tmp, '-');
			if (p == NULL) {
				if (mail_host_add(*tmp) < 0)
					ret = -1;
			} else if (mail_hosts_add_range(t_strdup_until(*tmp, p),
							p + 1) < 0)
				ret = -1;
		}
	} T_END;

	if (array_count(&hosts) == 0) {
		if (ret < 0)
			i_error("No valid servers specified");
		else
			i_error("Empty server list");
		ret = -1;
	}
	return ret;
}

void mail_host_set_vhost_count(struct mail_host *host,
			       unsigned int vhost_count)
{
	host->vhost_count = vhost_count;
	mail_hosts_sort();
}

void mail_host_remove(struct mail_host *host)
{
	struct mail_host *const *h;
	unsigned int i, count;

	h = array_get(&hosts, &count);
	for (i = 0; i < count; i++) {
		if (h[i] == host) {
			array_delete(&hosts, i, 1);
			break;
		}
	}

	i_free(host);
	mail_hosts_sort();
}

struct mail_host *mail_host_lookup(const struct ip_addr *ip)
{
	struct mail_host *const *hostp;

	if (hosts_unsorted)
		mail_hosts_sort();

	array_foreach(&hosts, hostp) {
		if (net_ip_compare(&(*hostp)->ip, ip))
			return *hostp;
	}
	return NULL;
}

struct mail_host *mail_host_get_by_hash(unsigned int hash)
{
	struct mail_host *const *v;
	unsigned int count;

	if (hosts_unsorted)
		mail_hosts_sort();

	v = array_get(&vhosts, &count);
	if (count == 0)
		return NULL;

	return v[hash % count];
}

const ARRAY_TYPE(mail_host) *mail_hosts_get(void)
{
	if (hosts_unsorted)
		mail_hosts_sort();
	return &hosts;
}

void mail_hosts_init(void)
{
	i_array_init(&hosts, 16);
	i_array_init(&vhosts, 16*VHOST_MULTIPLIER);
}

void mail_hosts_deinit(void)
{
	struct mail_host **hostp;

	array_foreach_modifiable(&hosts, hostp)
		i_free(*hostp);
	array_free(&hosts);
	array_free(&vhosts);
}
