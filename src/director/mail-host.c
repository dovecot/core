/* Copyright (c) 2010-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "md5.h"
#include "mail-host.h"

#define VHOST_MULTIPLIER 100

struct mail_vhost {
	unsigned int hash;
	struct mail_host *host;
};

struct mail_host_list {
	ARRAY_TYPE(mail_host) hosts;
	ARRAY(struct mail_vhost) vhosts;
	bool hosts_unsorted;
	bool consistent_hashing;
};

static int
mail_host_cmp(struct mail_host *const *h1, struct mail_host *const *h2)
{
	return net_ip_cmp(&(*h1)->ip, &(*h2)->ip);
}

static int
mail_vhost_cmp(const struct mail_vhost *h1, const struct mail_vhost *h2)
{
	if (h1->hash < h2->hash)
		return -1;
	else if (h1->hash > h2->hash)
		return 1;
	/* hash collision. not ideal, but we'll need to keep the order
	   consistent across directors so compare the IPs next. */
	return net_ip_cmp(&h1->host->ip, &h2->host->ip);
}

static int
mail_vhost_hash_cmp(const unsigned int *hash, const struct mail_vhost *vhost)
{
	if (vhost->hash < *hash)
		return 1;
	else if (vhost->hash > *hash)
		return -1;
	else
		return 0;
}

static void mail_vhost_add(struct mail_host_list *list, struct mail_host *host)
{
	struct mail_vhost *vhost;
	struct md5_context md5_ctx, md5_ctx2;
	unsigned char md5[MD5_RESULTLEN];
	const char *ip_str;
	char num_str[MAX_INT_STRLEN];
	unsigned int i, j;

	if (host->down)
		return;

	ip_str = net_ip2addr(&host->ip);

	md5_init(&md5_ctx);
	md5_update(&md5_ctx, ip_str, strlen(ip_str));

	for (i = 0; i < host->vhost_count; i++) {
		md5_ctx2 = md5_ctx;
		i_snprintf(num_str, sizeof(num_str), "-%u", i);
		md5_update(&md5_ctx2, num_str, strlen(num_str));
		md5_final(&md5_ctx2, md5);

		vhost = array_append_space(&list->vhosts);
		vhost->host = host;
		for (j = 0; j < sizeof(vhost->hash); j++)
			vhost->hash = (vhost->hash << CHAR_BIT) | md5[j];
	}
}

static void mail_hosts_sort_ring(struct mail_host_list *list)
{
	struct mail_host *const *hostp;

	/* rebuild vhosts */
	array_clear(&list->vhosts);
	array_foreach(&list->hosts, hostp)
		mail_vhost_add(list, *hostp);
	array_sort(&list->vhosts, mail_vhost_cmp);
	list->hosts_unsorted = FALSE;
}

static void mail_hosts_sort_direct(struct mail_host_list *list)
{
	struct mail_vhost *vhost;
	struct mail_host *const *hostp;
	unsigned int i;

	array_sort(&list->hosts, mail_host_cmp);

	/* rebuild vhosts */
	array_clear(&list->vhosts);
	array_foreach(&list->hosts, hostp) {
		if ((*hostp)->down)
			continue;
		for (i = 0; i < (*hostp)->vhost_count; i++) {
			vhost = array_append_space(&list->vhosts);
			vhost->host = *hostp;
		}
	}
	list->hosts_unsorted = FALSE;
}

static void mail_hosts_sort(struct mail_host_list *list)
{
	if (list->consistent_hashing)
		mail_hosts_sort_ring(list);
	else
		mail_hosts_sort_direct(list);
}

struct mail_host *
mail_host_add_ip(struct mail_host_list *list, const struct ip_addr *ip,
		 const char *tag)
{
	struct mail_host *host;

	i_assert(tag != NULL);

	host = i_new(struct mail_host, 1);
	host->vhost_count = VHOST_MULTIPLIER;
	host->ip = *ip;
	host->tag = i_strdup(tag);
	array_append(&list->hosts, &host, 1);

	list->hosts_unsorted = TRUE;
	return host;
}

static int
mail_host_add(struct mail_host_list *list, const char *host, const char *tag)
{
	struct ip_addr *ips;
	unsigned int i, ips_count;

	if (net_gethostbyname(host, &ips, &ips_count) < 0) {
		i_error("Unknown mail host: %s", host);
		return -1;
	}

	for (i = 0; i < ips_count; i++)
		(void)mail_host_add_ip(list, &ips[i], tag);
	return 0;
}

static int
mail_hosts_add_range(struct mail_host_list *list,
		     struct ip_addr ip1, struct ip_addr ip2, const char *tag)
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
		if ((i1 & (1U << j)) != (i2 & (1U << j))) {
			i_error("IP address range too large: %s-%s",
				net_ip2addr(&ip1), net_ip2addr(&ip2));
			return -1;
		}
	}

	/* create hosts from the final bits */
	do {
		ip1_arr[i] = ntohl(i1);
		(void)mail_host_add_ip(list, &ip1, tag);
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
			const char *tag, *value = *tmp;

			p = strchr(value, '@');
			if (p == NULL)
				tag = "";
			else {
				value = t_strdup_until(value, p++);
				tag = p;
			}
			p = strchr(value, '-');
			if (p != NULL) {
				/* see if this is ip1-ip2 range */
				host1 = t_strdup_until(value, p);
				host2 = p + 1;
				if (net_addr2ip(host1, &ip1) == 0 &&
				    net_addr2ip(host2, &ip2) == 0) {
					if (mail_hosts_add_range(list, ip1, ip2,
								 tag) < 0)
						ret = -1;
					continue;
				}
			}

			if (mail_host_add(list, value, tag) < 0)
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

void mail_host_set_tag(struct mail_host *host, const char *tag)
{
	i_assert(tag != NULL);

	i_free(host->tag);
	host->tag = i_strdup(tag);
}

void mail_host_set_down(struct mail_host_list *list,
			struct mail_host *host, bool down, time_t timestamp)
{
	if (host->down != down) {
		host->down = down;
		host->last_updown_change = timestamp;
		list->hosts_unsorted = TRUE;
	}
}

void mail_host_set_vhost_count(struct mail_host_list *list,
			       struct mail_host *host, unsigned int vhost_count)
{
	host->vhost_count = vhost_count;
	list->hosts_unsorted = TRUE;
}

static void mail_host_free(struct mail_host *host)
{
	i_free(host->tag);
	i_free(host);
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

	mail_host_free(host);
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

static struct mail_host *
mail_host_get_by_hash_ring(struct mail_host_list *list, unsigned int hash,
			   const char *tag)
{
	struct mail_host *host;
	const struct mail_vhost *vhosts;
	unsigned int i, count, idx;

	vhosts = array_get(&list->vhosts, &count);
	array_bsearch_insert_pos(&list->vhosts, &hash,
				 mail_vhost_hash_cmp, &idx);
	i_assert(idx <= count);
	if (idx == count) {
		if (count == 0)
			return NULL;
		idx = 0;
	}

	for (i = 0; i < count; i++) {
		host = vhosts[(idx + i) % count].host;
		if (strcmp(host->tag, tag) == 0)
			return host;
	}
	return NULL;
}

static struct mail_host *
mail_host_get_by_hash_direct(struct mail_host_list *list, unsigned int hash,
			     const char *tag)
{
	struct mail_host *host;
	const struct mail_vhost *vhosts;
	unsigned int i, count;

	vhosts = array_get(&list->vhosts, &count);
	if (count == 0)
		return NULL;

	for (i = 0; i < count; i++) {
		host = vhosts[(hash + i) % count].host;
		if (strcmp(host->tag, tag) == 0)
			return host;
	}
	return NULL;
}

struct mail_host *
mail_host_get_by_hash(struct mail_host_list *list, unsigned int hash,
		      const char *tag)
{
	if (list->hosts_unsorted)
		mail_hosts_sort(list);

	if (list->consistent_hashing)
		return mail_host_get_by_hash_ring(list, hash, tag);
	else
		return mail_host_get_by_hash_direct(list, hash, tag);
}

bool mail_hosts_have_usable(struct mail_host_list *list)
{
	if (list->hosts_unsorted)
		mail_hosts_sort(list);
	return array_count(&list->vhosts) > 0;
}

const ARRAY_TYPE(mail_host) *mail_hosts_get(struct mail_host_list *list)
{
	if (list->hosts_unsorted)
		mail_hosts_sort(list);
	return &list->hosts;
}

struct mail_host_list *mail_hosts_init(bool consistent_hashing)
{
	struct mail_host_list *list;

	list = i_new(struct mail_host_list, 1);
	list->consistent_hashing = consistent_hashing;
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
		mail_host_free(*hostp);
	array_free(&list->hosts);
	array_free(&list->vhosts);
	i_free(list);
}

static struct mail_host *mail_host_dup(const struct mail_host *src)
{
	struct mail_host *dest;

	dest = i_new(struct mail_host, 1);
	*dest = *src;
	dest->tag = i_strdup(src->tag);
	return dest;
}

struct mail_host_list *mail_hosts_dup(const struct mail_host_list *src)
{
	struct mail_host_list *dest;
	struct mail_host *const *hostp, *dest_host;

	dest = mail_hosts_init(src->consistent_hashing);
	array_foreach(&src->hosts, hostp) {
		dest_host = mail_host_dup(*hostp);
		array_append(&dest->hosts, &dest_host, 1);
	}
	mail_hosts_sort(dest);
	return dest;
}
