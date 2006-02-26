/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "home-expand.h"
#include "mail-search.h"
#include "quota-private.h"
#include "quota-plugin.h"
#include "trash-plugin.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define LOCAL_CONFIG_FILE "~/.dovecot.trash.conf"
#define GLOBAL_CONFIG_FILE "/etc/dovecot-trash.conf"

#define MAX_RETRY_COUNT 3

#define TRASH_CONTEXT(obj) \
	*((void **)array_idx_modifyable(&(obj)->quota_module_contexts, \
					trash_quota_module_id))

struct trash_quota {
	struct quota super;
};

struct trash_mailbox {
	const char *name;
	int priority; /* lower number = higher priority */

	struct mail_storage *storage;

	/* temporarily set while cleaning: */
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;
	struct mail *mail;

	unsigned int mail_set:1;
};

/* defined by imap, pop3, lda */
extern void (*hook_mail_storage_created)(struct mail_storage *storage);

static void (*trash_next_hook_mail_storage_created)
	(struct mail_storage *storage);
static bool quota_initialized;
static unsigned int trash_quota_module_id;

static pool_t config_pool;
/* trash_boxes ordered by priority, highest first */
static array_t ARRAY_DEFINE(trash_boxes, struct trash_mailbox);

static int trash_clean_mailbox_open(struct trash_mailbox *trash)
{
        struct mail_search_arg search_arg;

	trash->box = mailbox_open(trash->storage, trash->name, NULL,
				  MAILBOX_OPEN_KEEP_RECENT);
	trash->trans = mailbox_transaction_begin(trash->box, 0);

	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_ALL;

	trash->search_ctx =
		mailbox_search_init(trash->trans, NULL, &search_arg, NULL);
	trash->mail = mail_alloc(trash->trans, MAIL_FETCH_PHYSICAL_SIZE |
				 MAIL_FETCH_RECEIVED_DATE, NULL);

	return mailbox_search_next(trash->search_ctx, trash->mail);
}

static int trash_clean_mailbox_get_next(struct trash_mailbox *trash,
					time_t *received_time_r)
{
	int ret;

	if (!trash->mail_set) {
		if (trash->box == NULL)
			ret = trash_clean_mailbox_open(trash);
		else
			ret = mailbox_search_next(trash->search_ctx,
						  trash->mail);
		if (ret <= 0)
			return ret;

		trash->mail_set = TRUE;
	}

	*received_time_r = mail_get_received_date(trash->mail);
	return 1;
}

static int trash_try_clean_mails(uint64_t size_needed)
{
	struct trash_mailbox *trashes;
	unsigned int i, j, count, oldest_idx;
	time_t oldest, received;
	uint64_t size;
	int ret = 0;

	trashes = array_get_modifyable(&trash_boxes, &count);
	for (i = 0; i < count; ) {
		/* expunge oldest mails first in all trash boxes with
		   same priority */
		oldest_idx = count;
		oldest = (time_t)-1;
		for (j = i; j < count; j++) {
			if (trashes[j].priority != trashes[j].priority)
				break;

			ret = trash_clean_mailbox_get_next(&trashes[i],
							   &received);
			if (ret < 0)
				goto __err;
			if (ret > 0) {
				if (oldest == (time_t)-1 ||
				    received < oldest) {
					oldest = received;
					oldest_idx = j;
				}
			}
		}

		if (oldest_idx < count) {
			if (mail_expunge(trashes[oldest_idx].mail) < 0)
				break;

			size = mail_get_physical_size(trashes[oldest_idx].mail);
			if (size >= size_needed) {
				size_needed = 0;
				break;
			}
			trashes[oldest_idx].mail_set = FALSE;

			size_needed -= size;
		} else {
			/* find more mails from next priority's mailbox */
			i = j;
		}
	}

__err:
	for (i = 0; i < count; i++) {
		struct trash_mailbox *trash = &trashes[i];

		mail_free(&trash->mail);
		(void)mailbox_search_deinit(&trash->search_ctx);

		if (size_needed == 0) {
			(void)mailbox_transaction_commit(&trash->trans,
				MAILBOX_SYNC_FLAG_FULL_WRITE);
		} else {
			/* couldn't get enough space, don't expunge anything */
                        mailbox_transaction_rollback(&trash->trans);
		}

		mailbox_close(&trash->box);
	}
	return size_needed == 0;
}

static int
trash_quota_try_alloc(struct quota_transaction_context *ctx,
		      struct mail *mail, bool *too_large_r)
{
	struct trash_quota *tquota = TRASH_CONTEXT(quota);
	int ret, i;

	for (i = 0; ; i++) {
		ret = tquota->super.try_alloc(ctx, mail, too_large_r);
		if (ret != 0 || *too_large_r)
			return ret;

		if (i == MAX_RETRY_COUNT) {
			/* trash_try_clean_mails() should have returned 0 if
			   it couldn't get enough space, but allow retrying
			   it a couple of times if there was some extra space
			   that was needed.. */
			break;
		}

		/* not enough space. try deleting some from mailbox. */
		ret = trash_try_clean_mails(mail_get_physical_size(mail));
		if (ret <= 0)
			return 0;
	}

	return 0;
}

static void trash_quota_deinit(struct quota *quota)
{
	struct trash_quota *tquota = TRASH_CONTEXT(quota);
	void *null = NULL;

	array_idx_set(&quota->quota_module_contexts,
		      trash_quota_module_id, &null);
	tquota->super.deinit(quota);
	i_free(tquota);
}

static void trash_mail_storage_created(struct mail_storage *storage)
{
	struct trash_quota *tquota;

	if (trash_next_hook_mail_storage_created != NULL)
		trash_next_hook_mail_storage_created(storage);

	if (quota_initialized || quota == NULL)
		return;

	/* initialize here because plugins could be loaded in wrong order */
	quota_initialized = TRUE;

	tquota = i_new(struct trash_quota, 1);
	tquota->super = *quota;
	quota->deinit = trash_quota_deinit;
	quota->try_alloc = trash_quota_try_alloc;

	trash_quota_module_id = quota_module_id++;
	array_idx_set(&quota->quota_module_contexts,
		      trash_quota_module_id, &tquota);
}

static int trash_mailbox_priority_cmp(const void *p1, const void *p2)
{
	const struct trash_mailbox *t1 = p1, *t2 = p2;

	return t1->priority - t2->priority;
}

static int read_configuration(const char *path)
{
	struct istream *input;
	const char *line, *name;
	struct trash_mailbox *trash;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT)
			i_error("open(%s) failed: %m", path);
		return -1;
	}

	p_clear(config_pool);
	ARRAY_CREATE(&trash_boxes, config_pool, struct trash_mailbox, 8);

	input = i_stream_create_file(fd, default_pool, (size_t)-1, FALSE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		/* <priority> <mailbox name> */
		name = strchr(line, ' ');
		if (name == NULL || name[1] == '\0')
			continue;

		trash = array_append_space(&trash_boxes);
		trash->name = p_strdup(config_pool, name+1);
		trash->priority = atoi(t_strdup_until(line, name));
	}
	i_stream_destroy(&input);
	(void)close(fd);

	qsort(array_get_modifyable(&trash_boxes, NULL),
	      array_count(&trash_boxes), sizeof(struct trash_mailbox),
	      trash_mailbox_priority_cmp);
	return 0;
}

void trash_plugin_init(void)
{
	quota_initialized = FALSE;
	trash_next_hook_mail_storage_created = hook_mail_storage_created;

	config_pool = pool_alloconly_create("trash config", 1024);
	if (read_configuration(home_expand(LOCAL_CONFIG_FILE)) < 0) {
		if (read_configuration(GLOBAL_CONFIG_FILE) < 0)
			return;
	}

	hook_mail_storage_created = trash_mail_storage_created;
}

void trash_plugin_deinit(void)
{
	pool_unref(config_pool);
	hook_mail_storage_created = trash_next_hook_mail_storage_created;
}
