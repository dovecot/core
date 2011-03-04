/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-host.h"

#define VHOST_MULTIPLIER 100

struct mail_host_list {
	ARRAY_TYPE(mail_host) hosts;
	ARRAY_DEFINE(vhosts, struct mail_host *);
	bool hosts_unsorted;
};

static int
mail_host_cmp(struct mail_host *const *h1, struct mail_host *const *h2)
{
	return net_ip_cmp(&(*h1)->ip, &(*h2)->ip);
}

static void mail_hosts_sort(struct mail_host_list *list)
{
	struct mail_host *const *hostp;
	unsigned int i;

	array_sort(&list->hosts, mail_host_cmp);

	/* rebuild vhosts */
	array_clear(&list->vhosts);
	array_foreach(&list->hosts, hostp) {
		for (i = 0; i < (*hostp)->vhost_count; i++)
			array_append(&list->vhosts, hostp, 1);
	}
	list->hosts_unsorted = FALSE;
}

struct mail_host *
mail_host_add_ip(struct mail_host_list *list, const struct ip_addr *ip)
{
	struct mail_host *host;

	host = i_new(struct mail_host, 1);
	host->vhost_count = VHOST_MULTIPLIER;
	host->ip = *ip;
	array_append(&list->hosts, &host, 1);

	list->hosts_unsorted = TRUE;
	return host;
}

static int mail_host_add(struct mail_host_list *list, const char *host)
{
	struct ip_addr *ips;
	unsigned int i, ips_count;

	if (net_gethostbyname(host, &ips, &ips_count) < 0) {
		i_error("Unknown mail host: %s", host);
		return -1;
	}

	for (i = 0; i < ips_count; i++)
		mail_host_add_ip(list, &ips[i]);
	return 0;
}

static int
mail_hosts_add_range(struct mail_host_list *list,
		     struct ip_addr ip1, struct ip_addr ip2)
{
	uint32_t *ip1_arr, *ip2_arr;
	uint32_t i1, i2;
	unsigned int i, j, max_bits, last_bits;

	if (ip1.family != ip2.family) {
		i_error("IP address family mismatch: %s vs %s",
			net_ip2addr(&ip1), net_ip2addr(&ip2));
		return -1;
	}
	if (net_ip_cmp(&ip1, &ip2) > 0) {
		i_error("IP addresses reversed: %s-%s",
			net_ip2addr(&ip1), net_ip2addr(&ip2));
		return -1;
	}
	if (IPADDR_IS_V4(&ip1)) {
		ip1_arr = &ip1.u.ip4.s_addr;
		ip2_arr = &ip2.u.ip4.s_addr;
		max_bits = 32;
		last_bits = 8;
	} else {
#ifndef HAVE_IPV6
		i_error("IPv6 not supported");
		return -1;
#else
		ip1_arr = (void *)&ip1.u.ip6;
		ip2_arr = (void *)&ip2.u.ip6;
		max_bits = 128;
		last_bits = 16;
#endif
	}

	/* make sure initial bits match */
	for (i = 0; i < (max_bits-last_bits)/32; i++) {
		if (ip1_arr[i] != ip2_arr[i]) {
			i_error("IP address range too large: %s-%s",
				net_ip2addr(&ip1), net_ip2addr(&ip2));
			return -1;
		}
	}
	i1 = htonl(ip1_arr[i]);
	i2 = htonl(ip2_arr[i]);

	for (j = last_bits; j < 32; j++) {
		if ((i1 & (1 << j)) != (i2 & (1 << j))) {
			i_error("IP address range too large: %s-%s",
				net_ip2addr(&ip1), net_ip2addr(&ip2));
			return -1;
		}
	}

	/* create hosts from the final bits */
	do {
		ip1_arr[i] = ntohl(i1);
		mail_host_add_ip(list, &ip1);
		i1++;
	} while (ip1_arr[i] != ip2_arr[i]);
	return 0;
}

int mail_hosts_parse_and_add(struct mail_host_list *list,
			     const char *hosts_string)
{
	int ret = 0;

	T_BEGIN {
		const char *const *tmp, *p, *host1, *host2;
		struct ip_addr ip1, ip2;

		tmp = t_strsplit_spaces(hosts_string, " ");
		for (; *tmp != NULL; tmp++) {
			p = strchr(*tmp, '-');
			if (p != NULL) {
				/* see if this is ip1-ip2 range */
				host1 = t_strdup_until(*tmp, p);
				host2 = p + 1;
				if (net_addr2ip(host1, &ip1) == 0 &&
				    net_addr2ip(host2, &ip2) == 0) {
					if (mail_hosts_add_range(list, ip1,
								 ip2) < 0)
						ret = -1;
					continue;
				}
			}

			if (mail_host_add(list, *tmp) < 0)
				ret = -1;
		}
	} T_END;

	if (array_count(&list->hosts) == 0) {
		if (ret < 0)
			i_error("No valid servers specified");
		else
			i_error("Empty server list");
		ret = -1;
	}
	return ret;
}

void mail_host_set_vhost_count(struct mail_host_list *list,
			       struct mail_host *host, unsigned int vhost_count)
{
	host->vhost_count = vhost_count;
	list->hosts_unsorted = TRUE;
}

void mail_host_remove(struct mail_host_list *list, struct mail_host *host)
{
	struct mail_host *const *hosts;
	unsigned int i, count;

	hosts = array_get(&list->hosts, &count);
	for (i = 0; i < count; i++) {
		if (hosts[i] == host) {
			array_delete(&list->hosts, i, 1);
			break;
		}
	}

	i_free(host);
	list->hosts_unsorted = TRUE;
}

struct mail_host *
mail_host_lookup(struct mail_host_list *list, const struct ip_addr *ip)
{
	struct mail_host *const *hostp;

	if (list->hosts_unsorted)
		mail_hosts_sort(list);

	array_foreach(&list->hosts, hostp) {
		if (net_ip_compare(&(*hostp)->ip, ip))
			return *hostp;
	}
	return NULL;
}

struct mail_host *
mail_host_get_by_hash(struct mail_host_list *list, unsigned int hash)
{
	struct mail_host *const *vhosts;
	unsigned int count;

	if (list->hosts_unsorted)
		mail_hosts_sort(list);

	vhosts = array_get(&list->vhosts, &count);
	if (count == 0)
		return NULL;

	return vhosts[hash % count];
}

const ARRAY_TYPE(mail_host) *mail_hosts_get(struct mail_host_list *list)
{
	if (list->hosts_unsorted)
		mail_hosts_sort(list);
	return &list->hosts;
}

struct mail_host_list *mail_hosts_init(void)
{
	struct mail_host_list *list;

	list = i_new(struct mail_host_list, 1);
	i_array_init(&list->hosts, 16);
	i_array_init(&list->vhosts, 16*VHOST_MULTIPLIER);
	return list;
}

void mail_hosts_deinit(struct mail_host_list **_list)
{
	struct mail_host_list *list = *_list;
	struct mail_host **hostp;

	*_list = NULL;

	array_foreach_modifiable(&list->hosts, hostp)
		i_free(*hostp);
	array_free(&list->hosts);
	array_free(&list->vhosts);
	i_free(list);
}

static struct mail_host *mail_host_dup(const struct mail_host *src)
{
	struct mail_host *dest;

	dest = i_new(struct mail_host, 1);
	*dest = *src;
	return dest;
}

struct mail_host_list *mail_hosts_dup(const struct mail_host_list *src)
{
	struct mail_host_list *dest;
	struct mail_host *const *hostp, *dest_host;

	dest = mail_hosts_init();
	array_foreach(&src->hosts, hostp) {
		dest_host = mail_host_dup(*hostp);
		array_append(&dest->hosts, &dest_host, 1);
	}
	mail_hosts_sort(dest);
	return dest;
}
