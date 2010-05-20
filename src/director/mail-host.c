/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

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
	struct ip_addr ip;

	if (net_addr2ip(host, &ip) < 0) {
		i_error("Invalid IP address: %s", host);
		return -1;
	}

	mail_host_add_ip(list, &ip);
	return 0;
}

static int
mail_hosts_add_range(struct mail_host_list *list, const char *host1, const char *host2)
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

int mail_hosts_parse_and_add(struct mail_host_list *list,
			     const char *hosts_string)
{
	int ret = 0;

	T_BEGIN {
		const char *const *tmp, *p;

		tmp = t_strsplit_spaces(hosts_string, " ");
		for (; *tmp != NULL; tmp++) {
			p = strchr(*tmp, '-');
			if (p == NULL) {
				if (mail_host_add(list, *tmp) < 0)
					ret = -1;
			} else if (mail_hosts_add_range(list, t_strdup_until(*tmp, p),
							p + 1) < 0)
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
	mail_hosts_sort(list);
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
	mail_hosts_sort(list);
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
