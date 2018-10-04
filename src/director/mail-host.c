/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "crc32.h"
#include "md5.h"
#include "user-directory.h"
#include "mail-host.h"

#define VHOST_MULTIPLIER 100

struct mail_host_list {
	ARRAY_TYPE(mail_tag) tags;
	ARRAY_TYPE(mail_host) hosts;
	user_free_hook_t *user_free_hook;
	unsigned int hosts_hash;
	unsigned int user_expire_secs;
	bool vhosts_unsorted;
	bool have_vhosts;
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

static void mail_vhost_add(struct mail_tag *tag, struct mail_host *host)
{
	struct mail_vhost *vhost;
	struct md5_context md5_ctx, md5_ctx2;
	unsigned char md5[MD5_RESULTLEN];
	char num_str[MAX_INT_STRLEN];
	unsigned int i, j;

	if (host->down || host->tag != tag)
		return;

	md5_init(&md5_ctx);
	md5_update(&md5_ctx, host->ip_str, strlen(host->ip_str));

	for (i = 0; i < host->vhost_count; i++) {
		md5_ctx2 = md5_ctx;
		i_snprintf(num_str, sizeof(num_str), "-%u", i);
		md5_update(&md5_ctx2, num_str, strlen(num_str));
		md5_final(&md5_ctx2, md5);

		vhost = array_append_space(&tag->vhosts);
		vhost->host = host;
		for (j = 0; j < sizeof(vhost->hash); j++)
			vhost->hash = (vhost->hash << CHAR_BIT) | md5[j];
	}
}

static void
mail_tag_vhosts_sort_ring(struct mail_host_list *list, struct mail_tag *tag)
{
	struct mail_host *const *hostp;

	/* rebuild vhosts */
	array_clear(&tag->vhosts);
	array_foreach(&list->hosts, hostp)
		mail_vhost_add(tag, *hostp);
	array_sort(&tag->vhosts, mail_vhost_cmp);
}

static void
mail_hosts_sort(struct mail_host_list *list)
{
	struct mail_host *const *hostp;
	struct mail_tag *const *tagp;
	uint32_t num;

	array_sort(&list->hosts, mail_host_cmp);

	list->have_vhosts = FALSE;
	array_foreach(&list->tags, tagp) {
		mail_tag_vhosts_sort_ring(list, *tagp);
		if (array_count(&(*tagp)->vhosts) > 0)
			list->have_vhosts = TRUE;
	}
	list->vhosts_unsorted = FALSE;

	/* recalculate the hosts_hash */
	list->hosts_hash = 0;
	array_foreach(&list->hosts, hostp) {
		num = ((*hostp)->down ? 1 : 0) ^ (*hostp)->vhost_count;
		list->hosts_hash = crc32_data_more(list->hosts_hash,
						   &num, sizeof(num));
		num = net_ip_hash(&(*hostp)->ip);
		list->hosts_hash = crc32_data_more(list->hosts_hash,
						   &num, sizeof(num));
		list->hosts_hash = crc32_str_more(list->hosts_hash,
						  (*hostp)->tag->name);
	}
}

struct mail_tag *
mail_tag_find(struct mail_host_list *list, const char *tag_name)
{
	struct mail_tag *const *tagp;

	array_foreach(&list->tags, tagp) {
		if (strcmp((*tagp)->name, tag_name) == 0)
			return *tagp;
	}
	return NULL;
}

static struct mail_tag *
mail_tag_get(struct mail_host_list *list, const char *tag_name)
{
	struct mail_tag *tag;

	tag = mail_tag_find(list, tag_name);
	if (tag == NULL) {
		tag = i_new(struct mail_tag, 1);
		tag->name = i_strdup(tag_name);
		i_array_init(&tag->vhosts, 16*VHOST_MULTIPLIER);
		tag->users = user_directory_init(list->user_expire_secs,
						 list->user_free_hook);
		array_append(&list->tags, &tag, 1);
	}
	return tag;
}

static void mail_tag_free(struct mail_tag *tag)
{
	user_directory_deinit(&tag->users);
	array_free(&tag->vhosts);
	i_free(tag->name);
	i_free(tag);
}

struct mail_host *
mail_host_add_ip(struct mail_host_list *list, const struct ip_addr *ip,
		 const char *tag_name)
{
	struct mail_host *host;

	i_assert(tag_name != NULL);

	host = i_new(struct mail_host, 1);
	host->list = list;
	host->vhost_count = VHOST_MULTIPLIER;
	host->ip = *ip;
	host->ip_str = i_strdup(net_ip2addr(ip));
	host->tag = mail_tag_get(list, tag_name);
	array_append(&list->hosts, &host, 1);

	list->vhosts_unsorted = TRUE;
	return host;
}

struct mail_host *
mail_host_add_hostname(struct mail_host_list *list, const char *hostname,
		       const struct ip_addr *ip, const char *tag_name)
{
	struct mail_host *host;

	host = mail_host_add_ip(list, ip, tag_name);
	if (hostname != NULL && hostname[0] != '\0')
		host->hostname = i_strdup(hostname);
	return host;
}

static int
mail_host_add(struct mail_host_list *list, const char *hostname,
	      const char *tag_name)
{
	struct ip_addr *ips, ip;
	unsigned int i, ips_count;

	if (net_addr2ip(hostname, &ip) == 0) {
		(void)mail_host_add_ip(list, &ip, tag_name);
		return 0;
	}

	if (net_gethostbyname(hostname, &ips, &ips_count) < 0) {
		i_error("Unknown mail host: %s", hostname);
		return -1;
	}

	for (i = 0; i < ips_count; i++)
		(void)mail_host_add_hostname(list, hostname, &ips[i], tag_name);
	return 0;
}

static int
mail_hosts_add_range(struct mail_host_list *list,
		     struct ip_addr ip1, struct ip_addr ip2,
		     const char *tag_name)
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
		ip1_arr = (void *)&ip1.u.ip6;
		ip2_arr = (void *)&ip2.u.ip6;
		max_bits = 128;
		last_bits = 16;
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
		(void)mail_host_add_ip(list, &ip1, tag_name);
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

const char *mail_host_get_tag(const struct mail_host *host)
{
	return host->tag->name;
}

void mail_host_set_tag(struct mail_host *host, const char *tag_name)
{
	i_assert(tag_name != NULL);

	host->tag = mail_tag_get(host->list, tag_name);
	host->list->vhosts_unsorted = TRUE;
}

void mail_host_set_down(struct mail_host *host, bool down,
			time_t timestamp, const char *log_prefix)
{
	if (host->down != down) {
		const char *updown = down ? "down" : "up";
		i_info("%sHost %s changed %s "
		       "(vhost_count=%u last_updown_change=%ld)",
		       log_prefix, host->ip_str, updown,
		       host->vhost_count, (long)host->last_updown_change);

		host->down = down;
		host->last_updown_change = timestamp;
		host->list->vhosts_unsorted = TRUE;
	}
}

void mail_host_set_vhost_count(struct mail_host *host, unsigned int vhost_count,
			       const char *log_prefix)
{
	i_info("%sHost %s vhost count changed from %u to %u",
	       log_prefix, host->ip_str,
	       host->vhost_count, vhost_count);

	host->vhost_count = vhost_count;
	host->list->vhosts_unsorted = TRUE;
}

static void mail_host_free(struct mail_host *host)
{
	i_free(host->hostname);
	i_free(host->ip_str);
	i_free(host);
}

void mail_host_remove(struct mail_host *host)
{
	struct mail_host_list *list = host->list;
	struct mail_host *const *hosts;
	unsigned int i, count;

	hosts = array_get(&list->hosts, &count);
	for (i = 0; i < count; i++) {
		if (hosts[i] == host) {
			array_delete(&host->list->hosts, i, 1);
			break;
		}
	}
	mail_host_free(host);
	list->vhosts_unsorted = TRUE;
}

struct mail_host *
mail_host_lookup(struct mail_host_list *list, const struct ip_addr *ip)
{
	struct mail_host *const *hostp;

	if (list->vhosts_unsorted)
		mail_hosts_sort(list);

	array_foreach(&list->hosts, hostp) {
		if (net_ip_compare(&(*hostp)->ip, ip))
			return *hostp;
	}
	return NULL;
}

static struct mail_host *
mail_host_get_by_hash_ring(struct mail_tag *tag, unsigned int hash)
{
	const struct mail_vhost *vhosts;
	unsigned int count, idx;

	vhosts = array_get(&tag->vhosts, &count);
	array_bsearch_insert_pos(&tag->vhosts, &hash,
				 mail_vhost_hash_cmp, &idx);
	i_assert(idx <= count);
	if (idx == count) {
		if (count == 0)
			return NULL;
		idx = 0;
	}
	return vhosts[idx % count].host;
}

struct mail_host *
mail_host_get_by_hash(struct mail_host_list *list, unsigned int hash,
		      const char *tag_name)
{
	struct mail_tag *tag;

	if (list->vhosts_unsorted)
		mail_hosts_sort(list);

	tag = mail_tag_find(list, tag_name);
	if (tag == NULL)
		return NULL;

	return mail_host_get_by_hash_ring(tag, hash);
}

void mail_hosts_set_synced(struct mail_host_list *list)
{
	struct mail_host *const *hostp;

	array_foreach(&list->hosts, hostp)
		(*hostp)->desynced = FALSE;
}

unsigned int mail_hosts_hash(struct mail_host_list *list)
{
	if (list->vhosts_unsorted)
		mail_hosts_sort(list);
	/* don't return 0 as hash, since we're using it as "doesn't exist" in
	   some places. */
	return list->hosts_hash == 0 ? 1 : list->hosts_hash;
}

bool mail_hosts_have_usable(struct mail_host_list *list)
{
	if (list->vhosts_unsorted)
		mail_hosts_sort(list);
	return list->have_vhosts;
}

const ARRAY_TYPE(mail_host) *mail_hosts_get(struct mail_host_list *list)
{
	if (list->vhosts_unsorted)
		mail_hosts_sort(list);
	return &list->hosts;
}

bool mail_hosts_have_tags(struct mail_host_list *list)
{
	struct mail_tag *const *tagp;

	if (list->vhosts_unsorted)
		mail_hosts_sort(list);

	array_foreach(&list->tags, tagp) {
		if ((*tagp)->name[0] != '\0' && array_count(&(*tagp)->vhosts) > 0)
			return TRUE;
	}
	return FALSE;
}

const ARRAY_TYPE(mail_tag) *mail_hosts_get_tags(struct mail_host_list *list)
{
	return &list->tags;
}

struct mail_host_list *
mail_hosts_init(unsigned int user_expire_secs,
		user_free_hook_t *user_free_hook)
{
	struct mail_host_list *list;

	list = i_new(struct mail_host_list, 1);
	list->user_expire_secs = user_expire_secs;
	list->user_free_hook = user_free_hook;

	i_array_init(&list->hosts, 16);
	i_array_init(&list->tags, 4);
	return list;
}

void mail_hosts_deinit(struct mail_host_list **_list)
{
	struct mail_host_list *list = *_list;
	struct mail_host *const *hostp;
	struct mail_tag *const *tagp;

	*_list = NULL;

	array_foreach(&list->tags, tagp)
		mail_tag_free(*tagp);
	array_foreach(&list->hosts, hostp)
		mail_host_free(*hostp);
	array_free(&list->hosts);
	array_free(&list->tags);
	i_free(list);
}

static struct mail_host *
mail_host_dup(struct mail_host_list *dest_list, const struct mail_host *src)
{
	struct mail_host *dest;

	dest = i_new(struct mail_host, 1);
	*dest = *src;
	dest->tag = mail_tag_get(dest_list, src->tag->name);
	dest->ip_str = i_strdup(src->ip_str);
	dest->hostname = i_strdup(src->hostname);
	return dest;
}

struct mail_host_list *mail_hosts_dup(const struct mail_host_list *src)
{
	struct mail_host_list *dest;
	struct mail_host *const *hostp, *dest_host;

	dest = mail_hosts_init(src->user_expire_secs, src->user_free_hook);
	array_foreach(&src->hosts, hostp) {
		dest_host = mail_host_dup(dest, *hostp);
		array_append(&dest->hosts, &dest_host, 1);
	}
	mail_hosts_sort(dest);
	return dest;
}

void mail_hosts_sort_users(struct mail_host_list *list)
{
	struct mail_tag *const *tagp;

	array_foreach(&list->tags, tagp)
		user_directory_sort((*tagp)->users);
}
