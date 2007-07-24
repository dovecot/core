/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "home-expand.h"
#include "mail-namespace.h"
#include "mail-search.h"
#include "quota-private.h"
#include "quota-plugin.h"
#include "trash-plugin.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define INIT_TRASH_MAILBOX_COUNT 4
#define MAX_RETRY_COUNT 3

struct trash_mailbox {
	const char *name;
	int priority; /* lower number = higher priority */

	struct mail_storage *storage;

	/* temporarily set while cleaning: */
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
        struct mail_search_arg search_arg;
	struct mail_search_context *search_ctx;
	struct mail *mail;

	unsigned int mail_set:1;
};

const char *trash_plugin_version = PACKAGE_VERSION;

static int (*trash_next_quota_test_alloc)(struct quota_transaction_context *,
					  uoff_t, bool *);

static pool_t config_pool;
/* trash_boxes ordered by priority, highest first */
static ARRAY_DEFINE(trash_boxes, struct trash_mailbox);

static int sync_mailbox(struct mailbox *box)
{
	struct mailbox_sync_context *ctx;
        struct mailbox_sync_rec sync_rec;

	ctx = mailbox_sync_init(box, MAILBOX_SYNC_FLAG_FULL_READ);
	while (mailbox_sync_next(ctx, &sync_rec) > 0)
		;
	return mailbox_sync_deinit(&ctx, 0, NULL);
}

static int trash_clean_mailbox_open(struct trash_mailbox *trash)
{
	trash->box = mailbox_open(trash->storage, trash->name, NULL,
				  MAILBOX_OPEN_KEEP_RECENT);
	if (trash->box == NULL)
		return 0;

	if (sync_mailbox(trash->box) < 0)
		return -1;

	trash->trans = mailbox_transaction_begin(trash->box, 0);

	trash->search_ctx = mailbox_search_init(trash->trans, NULL,
						&trash->search_arg, NULL);
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
		if (ret <= 0) {
			*received_time_r = 0;
			return ret;
		}
		trash->mail_set = TRUE;
	}

	*received_time_r = mail_get_received_date(trash->mail);
	return 1;
}

static void trash_find_storage(struct trash_mailbox *trash)
{
	struct mail_storage *const *storages;
	unsigned int i, count;

	storages = array_get(&quota_set->storages, &count);
	for (i = 0; i < count; i++) {
		if (mail_namespace_update_name(storages[i]->ns, &trash->name)) {
			trash->storage = storages[i];
			return;
		}
	}
	i_fatal("trash: Namespace not found for mailbox '%s'", trash->name);
}

static int trash_try_clean_mails(struct quota_transaction_context *ctx,
				 uint64_t size_needed)
{
	struct trash_mailbox *trashes;
	unsigned int i, j, count, oldest_idx;
	time_t oldest, received = 0;
	uint64_t size, size_expunged = 0, expunged_count = 0;
	int ret = 0;

	trashes = array_get_modifiable(&trash_boxes, &count);
	for (i = 0; i < count; ) {
		/* expunge oldest mails first in all trash boxes with
		   same priority */
		oldest_idx = count;
		oldest = (time_t)-1;
		for (j = i; j < count; j++) {
			if (trashes[j].priority != trashes[i].priority)
				break;

			if (trashes[j].storage == NULL)
				trash_find_storage(&trashes[j]);

			ret = trash_clean_mailbox_get_next(&trashes[j],
							   &received);
			if (ret < 0)
				goto __err;
			if (ret > 0) {
				if (oldest == (time_t)-1 || received < oldest) {
					oldest = received;
					oldest_idx = j;
				}
			}
		}

		if (oldest_idx < count) {
			size = mail_get_physical_size(trashes[oldest_idx].mail);
			if (size == (uoff_t)-1) {
				/* maybe expunged already? */
				trashes[oldest_idx].mail_set = FALSE;
				continue;
			}

			if (mail_expunge(trashes[oldest_idx].mail) < 0)
				break;

			expunged_count++;
			size_expunged += size;
			if (size_expunged >= size_needed)
				break;
			trashes[oldest_idx].mail_set = FALSE;
		} else {
			/* find more mails from next priority's mailbox */
			i = j;
		}
	}

__err:
	for (i = 0; i < count; i++) {
		struct trash_mailbox *trash = &trashes[i];

		if (trash->box == NULL)
			continue;

		trash->mail_set = FALSE;
		mail_free(&trash->mail);
		(void)mailbox_search_deinit(&trash->search_ctx);

		if (size_expunged >= size_needed) {
			(void)mailbox_transaction_commit(&trash->trans,
				MAILBOX_SYNC_FLAG_FULL_WRITE);
		} else {
			/* couldn't get enough space, don't expunge anything */
                        mailbox_transaction_rollback(&trash->trans);
		}

		mailbox_close(&trash->box);
	}

	if (size_expunged < size_needed) {
		if (getenv("DEBUG") != NULL) {
			i_info("trash plugin: Failed to remove enough messages "
			       "(needed %llu bytes, expunged only %llu bytes)",
			       (unsigned long long)size_needed,
			       (unsigned long long)size_expunged);
		}
		return FALSE;
	}

	ctx->bytes_used = ctx->bytes_used > (int64_t)size_expunged ?
		ctx->bytes_used - size_expunged : 0;
	ctx->count_used = ctx->count_used > (int64_t)expunged_count ?
		ctx->count_used - expunged_count : 0;
	return TRUE;
}

static int
trash_quota_test_alloc(struct quota_transaction_context *ctx,
		       uoff_t size, bool *too_large_r)
{
	int ret, i;

	for (i = 0; ; i++) {
		ret = trash_next_quota_test_alloc(ctx, size, too_large_r);
		if (ret != 0 || *too_large_r) {
			if (getenv("DEBUG") != NULL && *too_large_r) {
				i_info("trash plugin: Mail is larger than "
				       "quota, won't even try to handle");
			}
			return ret;
		}

		if (i == MAX_RETRY_COUNT) {
			/* trash_try_clean_mails() should have returned 0 if
			   it couldn't get enough space, but allow retrying
			   it a couple of times if there was some extra space
			   that was needed.. */
			break;
		}

		/* not enough space. try deleting some from mailbox. */
		ret = trash_try_clean_mails(ctx, size);
		if (ret <= 0)
			return 0;
	}

	return 0;
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
	unsigned int count;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		i_error("open(%s) failed: %m", path);
		return -1;
	}

	p_clear(config_pool);
	p_array_init(&trash_boxes, config_pool, INIT_TRASH_MAILBOX_COUNT);

	input = i_stream_create_file(fd, (size_t)-1, FALSE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		/* <priority> <mailbox name> */
		name = strchr(line, ' ');
		if (name == NULL || name[1] == '\0')
			continue;

		trash = array_append_space(&trash_boxes);
		trash->name = p_strdup(config_pool, name+1);
		trash->priority = atoi(t_strdup_until(line, name));
		trash->search_arg.type = SEARCH_ALL;

		if (getenv("DEBUG") != NULL) {
			i_info("trash plugin: Added '%s' with priority %d",
			       trash->name, trash->priority);
		}
	}
	i_stream_destroy(&input);
	(void)close(fd);

	trash = array_get_modifiable(&trash_boxes, &count);
	qsort(trash, count, sizeof(*trash), trash_mailbox_priority_cmp);
	return 0;
}

void trash_plugin_init(void)
{
	const char *env;

	env = getenv("TRASH");
	if (env == NULL) {
		if (getenv("DEBUG") != NULL)
			i_info("trash plugin: No trash setting, disabled");
		return;
	}

	if (quota_set == NULL) {
		i_error("trash plugin: quota plugin not initialized");
		return;
	}

	config_pool = pool_alloconly_create("trash config",
					sizeof(trash_boxes) +
					BUFFER_APPROX_SIZE +
					INIT_TRASH_MAILBOX_COUNT *
					(sizeof(struct trash_mailbox) + 32));
	if (read_configuration(env) < 0)
		return;

	trash_next_quota_test_alloc = quota_set->test_alloc;
	quota_set->test_alloc = trash_quota_test_alloc;
}

void trash_plugin_deinit(void)
{
	quota_set->test_alloc = trash_next_quota_test_alloc;

	if (config_pool != NULL)
		pool_unref(config_pool);
}
