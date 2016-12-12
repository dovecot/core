/* Copyright (c) 2011-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "ioloop.h"
#include "hash.h"
#include "llist.h"
#include "base64.h"
#include "global-memory.h"
#include "stats-settings.h"
#include "mail-stats.h"
#include "mail-domain.h"
#include "mail-user.h"

static HASH_TABLE(char *, struct mail_user *) mail_users_hash;
/* users are sorted by their last_update timestamp, oldest first */
static struct mail_user *mail_users_head, *mail_users_tail;
struct mail_user *stable_mail_users;

static size_t mail_user_memsize(const struct mail_user *user)
{
	return sizeof(*user) + strlen(user->name) + 1;
}

struct mail_user *mail_user_login(const char *username)
{
	struct mail_user *user;
	const char *domain;

	user = hash_table_lookup(mail_users_hash, username);
	if (user != NULL) {
		mail_user_refresh(user, NULL);
		return user;
	}

	domain = i_strchr_to_next(username, '@');
	if (domain == NULL)
		domain = "";

	user = i_malloc(MALLOC_ADD(sizeof(struct mail_user), stats_alloc_size()));
	user->stats = (void *)(user + 1);
	user->name = i_strdup(username);
	user->reset_timestamp = ioloop_time;
	user->domain = mail_domain_login_create(domain);

	hash_table_insert(mail_users_hash, user->name, user);
	DLLIST_PREPEND_FULL(&stable_mail_users, user,
			    stable_prev, stable_next);
	DLLIST2_APPEND_FULL(&mail_users_head, &mail_users_tail, user,
			    sorted_prev, sorted_next);
	DLLIST_PREPEND_FULL(&user->domain->users, user,
			    domain_prev, domain_next);
	mail_domain_ref(user->domain);

	user->last_update = ioloop_timeval;
	global_memory_alloc(mail_user_memsize(user));
	return user;
}

void mail_user_disconnected(struct mail_user *user)
{
	mail_domain_disconnected(user->domain);
}

struct mail_user *mail_user_lookup(const char *username)
{
	return hash_table_lookup(mail_users_hash, username);
}

void mail_user_ref(struct mail_user *user)
{
	user->refcount++;
}

void mail_user_unref(struct mail_user **_user)
{
	struct mail_user *user = *_user;

	i_assert(user->refcount > 0);
	user->refcount--;

	*_user = NULL;
}

static void mail_user_free(struct mail_user *user)
{
	i_assert(user->refcount == 0);
	i_assert(user->sessions == NULL);

	global_memory_free(mail_user_memsize(user));
	hash_table_remove(mail_users_hash, user->name);
	DLLIST_REMOVE_FULL(&stable_mail_users, user,
			   stable_prev, stable_next);
	DLLIST2_REMOVE_FULL(&mail_users_head, &mail_users_tail, user,
			    sorted_prev, sorted_next);
	DLLIST_REMOVE_FULL(&user->domain->users, user,
			   domain_prev, domain_next);
	mail_domain_unref(&user->domain);

	i_free(user->name);
	i_free(user);
}

void mail_user_refresh(struct mail_user *user,
		       const struct stats *diff_stats)
{
	if (diff_stats != NULL)
		stats_add(user->stats, diff_stats);
	user->last_update = ioloop_timeval;
	DLLIST2_REMOVE_FULL(&mail_users_head, &mail_users_tail, user,
			    sorted_prev, sorted_next);
	DLLIST2_APPEND_FULL(&mail_users_head, &mail_users_tail, user,
			    sorted_prev, sorted_next);
	mail_domain_refresh(user->domain, diff_stats);
}

int mail_user_add_parse(const char *const *args, const char **error_r)
{
	struct mail_user *user;
	struct stats *empty_stats, *diff_stats;
	buffer_t *buf;
	const char *service, *error;

	/* <user> <service> <diff stats> */
	if (str_array_length(args) < 3) {
		*error_r = "ADD-USER: Too few parameters";
		return -1;
	}

	user = mail_user_login(args[0]);
	service = args[1];

	buf = buffer_create_dynamic(pool_datastack_create(), 256);
	if (base64_decode(args[2], strlen(args[2]), NULL, buf) < 0) {
		*error_r = t_strdup_printf("ADD-USER %s %s: Invalid base64 input",
					   user->name, service);
		return -1;
	}
	empty_stats = stats_alloc(pool_datastack_create());
	diff_stats = stats_alloc(pool_datastack_create());
	if (!stats_import(buf->data, buf->used, empty_stats, diff_stats, &error)) {
		*error_r = t_strdup_printf("ADD-USER %s %s: %s",
					   user->name, service, error);
		return -1;
	}
	mail_user_refresh(user, diff_stats);
	return 0;
}

void mail_users_free_memory(void)
{
	unsigned int diff;

	while (mail_users_head != NULL && mail_users_head->refcount == 0) {
		mail_user_free(mail_users_head);

		if (global_used_memory < stats_settings->memory_limit ||
		    mail_users_head == NULL)
			break;

		diff = ioloop_time - mail_users_head->last_update.tv_sec;
		if (diff < stats_settings->user_min_time)
			break;
	}
}

void mail_users_init(void)
{
	hash_table_create(&mail_users_hash, default_pool, 0, str_hash, strcmp);
}

void mail_users_deinit(void)
{
	while (mail_users_head != NULL)
		mail_user_free(mail_users_head);
	hash_table_destroy(&mail_users_hash);
}
