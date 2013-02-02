/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "llist.h"
#include "global-memory.h"
#include "stats-settings.h"
#include "mail-stats.h"
#include "mail-ip.h"

static HASH_TABLE(struct ip_addr *, struct mail_ip *) mail_ips_hash;
/* ips are sorted by their last_update timestamp, oldest first */
static struct mail_ip *mail_ips_head, *mail_ips_tail;
struct mail_ip *stable_mail_ips;

static size_t mail_ip_memsize(const struct mail_ip *ip)
{
	return sizeof(*ip);
}

struct mail_ip *mail_ip_login(const struct ip_addr *ip_addr)
{
	struct mail_ip *ip;

	ip = hash_table_lookup(mail_ips_hash, ip_addr);
	if (ip != NULL) {
		ip->num_logins++;
		mail_ip_refresh(ip, NULL);
		return ip;
	}

	ip = i_new(struct mail_ip, 1);
	ip->ip = *ip_addr;
	ip->reset_timestamp = ioloop_time;

	hash_table_insert(mail_ips_hash, &ip->ip, ip);
	DLLIST_PREPEND_FULL(&stable_mail_ips, ip, stable_prev, stable_next);
	DLLIST2_APPEND_FULL(&mail_ips_head, &mail_ips_tail, ip,
			    sorted_prev, sorted_next);
	ip->num_logins++;
	ip->last_update = ioloop_timeval;
	global_memory_alloc(mail_ip_memsize(ip));
	return ip;
}

struct mail_ip *mail_ip_lookup(const struct ip_addr *ip_addr)
{
	return hash_table_lookup(mail_ips_hash, ip_addr);
}

void mail_ip_ref(struct mail_ip *ip)
{
	ip->refcount++;
}

void mail_ip_unref(struct mail_ip **_ip)
{
	struct mail_ip *ip = *_ip;

	i_assert(ip->refcount > 0);
	ip->refcount--;

	*_ip = NULL;
}

static void mail_ip_free(struct mail_ip *ip)
{
	i_assert(ip->refcount == 0);
	i_assert(ip->sessions == NULL);

	global_memory_free(mail_ip_memsize(ip));
	hash_table_remove(mail_ips_hash, &ip->ip);
	DLLIST_REMOVE_FULL(&stable_mail_ips, ip, stable_prev, stable_next);
	DLLIST2_REMOVE_FULL(&mail_ips_head, &mail_ips_tail, ip,
			    sorted_prev, sorted_next);

	i_free(ip);
}

void mail_ip_refresh(struct mail_ip *ip, const struct mail_stats *diff_stats)
{
	if (diff_stats != NULL)
		mail_stats_add(&ip->stats, diff_stats);
	ip->last_update = ioloop_timeval;
	DLLIST2_REMOVE_FULL(&mail_ips_head, &mail_ips_tail, ip,
			    sorted_prev, sorted_next);
	DLLIST2_APPEND_FULL(&mail_ips_head, &mail_ips_tail, ip,
			    sorted_prev, sorted_next);
}

void mail_ips_free_memory(void)
{
	unsigned int diff;

	while (mail_ips_head != NULL && mail_ips_head->refcount == 0) {
		mail_ip_free(mail_ips_head);

		if (global_used_memory < stats_settings->memory_limit ||
		    mail_ips_head == NULL)
			break;

		diff = ioloop_time - mail_ips_head->last_update.tv_sec;
		if (diff < stats_settings->ip_min_time)
			break;
	}
}

void mail_ips_init(void)
{
	hash_table_create(&mail_ips_hash, default_pool, 0,
			  net_ip_hash, net_ip_cmp);
}

void mail_ips_deinit(void)
{
	while (mail_ips_head != NULL)
		mail_ip_free(mail_ips_head);
	hash_table_destroy(&mail_ips_hash);
}
