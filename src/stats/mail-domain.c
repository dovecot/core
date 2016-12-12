/* Copyright (c) 2011-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "llist.h"
#include "global-memory.h"
#include "stats-settings.h"
#include "mail-stats.h"
#include "mail-domain.h"

static HASH_TABLE(char *, struct mail_domain *) mail_domains_hash;
/* domains are sorted by their last_update timestamp, oldest first */
static struct mail_domain *mail_domains_head, *mail_domains_tail;
struct mail_domain *stable_mail_domains;

static size_t mail_domain_memsize(const struct mail_domain *domain)
{
	return sizeof(*domain) + strlen(domain->name) + 1;
}

struct mail_domain *mail_domain_login_create(const char *name)
{
	struct mail_domain *domain;

	domain = hash_table_lookup(mail_domains_hash, name);
	if (domain != NULL) {
		return domain;
	}

	domain = i_malloc(MALLOC_ADD(sizeof(struct mail_domain), stats_alloc_size()));
	domain->stats = (void *)(domain + 1);
	domain->name = i_strdup(name);
	domain->reset_timestamp = ioloop_time;

	hash_table_insert(mail_domains_hash, domain->name, domain);
	DLLIST_PREPEND_FULL(&stable_mail_domains, domain,
			    stable_prev, stable_next);
	global_memory_alloc(mail_domain_memsize(domain));
	return domain;
}

void mail_domain_login(struct mail_domain *domain)
{
	domain->num_logins++;
	domain->num_connected_sessions++;
	mail_domain_refresh(domain, NULL);
}

void mail_domain_disconnected(struct mail_domain *domain)
{
	i_assert(domain->num_connected_sessions > 0);
	domain->num_connected_sessions--;
	mail_global_disconnected();
}

struct mail_domain *mail_domain_lookup(const char *name)
{
	return hash_table_lookup(mail_domains_hash, name);
}

void mail_domain_ref(struct mail_domain *domain)
{
	domain->refcount++;
}

void mail_domain_unref(struct mail_domain **_domain)
{
	struct mail_domain *domain = *_domain;

	i_assert(domain->refcount > 0);
	domain->refcount--;

	*_domain = NULL;
}

static void mail_domain_free(struct mail_domain *domain)
{
	i_assert(domain->refcount == 0);
	i_assert(domain->users == NULL);

	global_memory_free(mail_domain_memsize(domain));
	hash_table_remove(mail_domains_hash, domain->name);
	DLLIST_REMOVE_FULL(&stable_mail_domains, domain,
			   stable_prev, stable_next);
	DLLIST2_REMOVE_FULL(&mail_domains_head, &mail_domains_tail, domain,
			    sorted_prev, sorted_next);

	i_free(domain->name);
	i_free(domain);
}

void mail_domain_refresh(struct mail_domain *domain,
			 const struct stats *diff_stats)
{
	if (diff_stats != NULL)
		stats_add(domain->stats, diff_stats);
	domain->last_update = ioloop_timeval;
	DLLIST2_REMOVE_FULL(&mail_domains_head, &mail_domains_tail, domain,
			    sorted_prev, sorted_next);
	DLLIST2_APPEND_FULL(&mail_domains_head, &mail_domains_tail, domain,
			    sorted_prev, sorted_next);
	mail_global_refresh(diff_stats);
}

void mail_domains_free_memory(void)
{
	unsigned int diff;

	while (mail_domains_head != NULL && mail_domains_head->refcount == 0) {
		mail_domain_free(mail_domains_head);

		if (global_used_memory < stats_settings->memory_limit ||
		    mail_domains_head == NULL)
			break;

		diff = ioloop_time - mail_domains_head->last_update.tv_sec;
		if (diff < stats_settings->domain_min_time)
			break;
	}
}

void mail_domains_init(void)
{
	hash_table_create(&mail_domains_hash, default_pool, 0, str_hash, strcmp);
}

void mail_domains_deinit(void)
{
	while (mail_domains_head != NULL)
		mail_domain_free(mail_domains_head);
	hash_table_destroy(&mail_domains_hash);
}
