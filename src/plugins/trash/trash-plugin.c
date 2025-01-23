/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "unichar.h"
#include "istream.h"
#include "settings.h"
#include "settings-parser.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "mailbox-list-private.h"
#include "quota-private.h"
#include "quota-plugin.h"
#include "trash-plugin.h"

#define INIT_TRASH_MAILBOX_COUNT 4
#define MAX_RETRY_COUNT 3

#define TRASH_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, trash_user_module)
#define TRASH_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, trash_user_module)

struct trash_mailbox {
	const char *name;
	unsigned int priority; /* lower number = higher priority */

	struct mail_namespace *ns;

	/* temporarily set while cleaning: */
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;
	struct mail *mail;
};

struct trash_user {
	union mail_user_module_context module_ctx;

	/* ordered by priority, highest first */
	ARRAY(struct trash_mailbox) trash_boxes;
};

struct trash_settings {
	pool_t pool;

	unsigned int trash_priority;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct trash_settings)
static const struct setting_define trash_setting_defines[] = {
	DEF(UINT, trash_priority),

	SETTING_DEFINE_LIST_END
};
static const struct trash_settings trash_default_settings = {
	.trash_priority = 0,
};

const struct setting_parser_info trash_setting_parser_info = {
	.name = "trash",

	.defines = trash_setting_defines,
	.defaults = &trash_default_settings,

	.struct_size = sizeof(struct trash_settings),
	.pool_offset1 = 1 + offsetof(struct trash_settings, pool),
};

const char *trash_plugin_version = DOVECOT_ABI_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(trash_user_module,
				  &mail_user_module_register);
static enum quota_alloc_result (*trash_next_quota_test_alloc)(
		struct quota_transaction_context *, uoff_t,
		const char **error_r);

static int trash_clean_mailbox_open(struct trash_mailbox *trash)
{
	struct mail_search_args *search_args;

	trash->box = mailbox_alloc(trash->ns->list, trash->name, 0);
	if (mailbox_open(trash->box) < 0) {
		mailbox_free(&trash->box);
		return 0;
	}

	if (mailbox_sync(trash->box, MAILBOX_SYNC_FLAG_FULL_READ) < 0)
		return -1;

	trash->trans = mailbox_transaction_begin(trash->box, 0, __func__);

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	trash->search_ctx = mailbox_search_init(trash->trans,
						search_args, NULL,
						MAIL_FETCH_PHYSICAL_SIZE |
						MAIL_FETCH_RECEIVED_DATE, NULL);
	mail_search_args_unref(&search_args);

	return mailbox_search_next(trash->search_ctx, &trash->mail) ? 1 : 0;
}

static int trash_clean_mailbox_get_next(struct trash_mailbox *trash,
					time_t *received_time_r)
{
	int ret;

	if (trash->mail == NULL) {
		if (trash->box == NULL)
			ret = trash_clean_mailbox_open(trash);
		else {
			ret = mailbox_search_next(trash->search_ctx,
						  &trash->mail) ? 1 : 0;
		}
		if (ret <= 0) {
			*received_time_r = 0;
			return ret;
		}
	}

	if (mail_get_received_date(trash->mail, received_time_r) < 0)
		return -1;
	return 1;
}

static int trash_try_clean_mails(struct quota_transaction_context *ctx,
				 uint64_t size_needed,
				 unsigned int count_needed)
{
	struct trash_user *tuser = TRASH_USER_CONTEXT_REQUIRE(ctx->quota->user);
	struct trash_mailbox *trashes;
	struct event_reason *reason;
	unsigned int i, j, count, oldest_idx;
	time_t oldest, received = 0;
	uint64_t size, size_expunged = 0;
	unsigned int expunged_count = 0;
	int ret = 0;

	reason = event_reason_begin("trash:clean");

	trashes = array_get_modifiable(&tuser->trash_boxes, &count);
	for (i = 0; i < count; ) {
		/* expunge oldest mails first in all trash boxes with
		   same priority */
		oldest_idx = count;
		oldest = (time_t)-1;
		for (j = i; j < count; j++) {
			if (trashes[j].priority != trashes[i].priority)
				break;

			ret = trash_clean_mailbox_get_next(&trashes[j],
							   &received);
			if (ret < 0)
				goto err;
			if (ret > 0) {
				if (oldest == (time_t)-1 || received < oldest) {
					oldest = received;
					oldest_idx = j;
				}
			}
		}

		if (oldest_idx < count) {
			if (mail_get_physical_size(trashes[oldest_idx].mail,
						   &size) < 0) {
				/* maybe expunged already? */
				trashes[oldest_idx].mail = NULL;
				continue;
			}

			mail_expunge(trashes[oldest_idx].mail);
			expunged_count++;
			size_expunged += size;
			if (size_expunged >= size_needed &&
			    expunged_count >= count_needed)
				break;
			trashes[oldest_idx].mail = NULL;
		} else {
			/* find more mails from next priority's mailbox */
			i = j;
		}
	}

err:
	for (i = 0; i < count; i++) {
		struct trash_mailbox *trash = &trashes[i];

		if (trash->box == NULL)
			continue;

		trash->mail = NULL;
		(void)mailbox_search_deinit(&trash->search_ctx);

		if (size_expunged >= size_needed &&
		    expunged_count >= count_needed) {
			(void)mailbox_transaction_commit(&trash->trans);
			(void)mailbox_sync(trash->box, 0);
		} else {
			/* couldn't get enough space, don't expunge anything */
                        mailbox_transaction_rollback(&trash->trans);
		}

		mailbox_free(&trash->box);
	}
	event_reason_end(&reason);

	if (size_expunged < size_needed) {
		e_debug(ctx->quota->user->event,
			"trash plugin: Failed to remove enough messages "
			"(needed %"PRIu64" bytes, expunged only %"PRIu64" bytes)",
			size_needed, size_expunged);
		return 0;
	}
	if (expunged_count < count_needed) {
		e_debug(ctx->quota->user->event,
			"trash plugin: Failed to remove enough messages "
			"(needed %u messages, expunged only %u messages)",
			count_needed, expunged_count);
		return 0;
	}

	if (ctx->bytes_over > 0) {
		/* user is over quota. drop the over-bytes first. */
		i_assert(ctx->bytes_over <= size_expunged);
		size_expunged -= ctx->bytes_over;
		ctx->bytes_over = 0;
	}
	if (ctx->count_over > 0) {
		/* user is over quota. drop the over-count first. */
		i_assert(ctx->count_over <= expunged_count);
		expunged_count -= ctx->count_over;
		ctx->count_over = 0;
	}

	if (ctx->bytes_ceil > ((uint64_t)-1 - size_expunged)) {
		ctx->bytes_ceil = (uint64_t)-1;
	} else {
		ctx->bytes_ceil += size_expunged;
	}
	if (ctx->count_ceil < ((uint64_t)-1 - expunged_count)) {
		ctx->count_ceil = (uint64_t)-1;
	} else {
		ctx->count_ceil += expunged_count;
	}
	return 1;
}

static enum quota_alloc_result
trash_quota_test_alloc(struct quota_transaction_context *ctx,
		       uoff_t size, const char **error_r)
{
	int i;
	uint64_t size_needed = 0;
	unsigned int count_needed = 0;

	for (i = 0; ; i++) {
		enum quota_alloc_result ret;
		ret = trash_next_quota_test_alloc(ctx, size, error_r);
		if (ret != QUOTA_ALLOC_RESULT_OVER_QUOTA) {
			if (ret == QUOTA_ALLOC_RESULT_OVER_QUOTA_LIMIT) {
				e_debug(ctx->quota->user->event,
					"trash plugin: Mail is larger than "
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

		if (ctx->bytes_ceil != (uint64_t)-1 &&
		    ctx->bytes_ceil < size + ctx->bytes_over)
			size_needed = size + ctx->bytes_over - ctx->bytes_ceil;
		if (ctx->count_ceil != (uint64_t)-1 &&
		    ctx->count_ceil < 1 + ctx->count_over)
			count_needed = 1 + ctx->count_over - ctx->count_ceil;

		/* not enough space. try deleting some from mailbox. */
		if (trash_try_clean_mails(ctx, size_needed, count_needed) <= 0) {
			*error_r = t_strdup_printf(
				"Allocating %"PRIuUOFF_T" bytes would exceed quota", size);
			return QUOTA_ALLOC_RESULT_OVER_QUOTA;
		}
	}
	*error_r = t_strdup_printf(
		"Allocating %"PRIuUOFF_T" bytes would exceed quota", size);
	return QUOTA_ALLOC_RESULT_OVER_QUOTA;
}

static int trash_mailbox_priority_cmp(const struct trash_mailbox *t1,
				      const struct trash_mailbox *t2)
{
	if (t1->priority < t2->priority)
		return -1;
	if (t1->priority > t2->priority)
		return 1;
	return strcmp(t1->name, t2->name);
}

static int trash_try_mailbox(struct mail_namespace *ns, const char *box_name,
			     const char **error_r)
{
	struct trash_user *tuser = TRASH_USER_CONTEXT_REQUIRE(ns->user);
	const struct trash_settings *trash_set;
	if (settings_try_get_filter(ns->list->event, "mailbox", box_name,
				    &trash_setting_parser_info, 0,
				    &trash_set, error_r) < 0)
		return -1;
	unsigned int trash_priority = trash_set->trash_priority;
	settings_free(trash_set);

	if (trash_priority == 0)
		return 0;

	const struct mailbox_settings *box_set;
	if (settings_try_get_filter(ns->list->event, "mailbox", box_name,
				    &mailbox_setting_parser_info, 0,
				    &box_set, error_r) < 0)
		return -1;

	const char *vname =
		mailbox_settings_get_vname(unsafe_data_stack_pool,
					   ns, box_set);
	struct trash_mailbox *trash =
		array_append_space(&tuser->trash_boxes);
	trash->ns = ns;
	trash->name = p_strdup(ns->user->pool, vname);
	trash->priority = trash_priority;

	settings_free(box_set);
	return 0;
}

static int trash_find_mailboxes(struct mail_user *user)
{
	struct trash_user *tuser = TRASH_USER_CONTEXT_REQUIRE(user);
	struct mail_namespace *ns;
	const char *box_name, *error;

	/* Find all configured mailboxes in all namespaces and try to find
	   trash_priority setting from them. */
	p_array_init(&tuser->trash_boxes, user->pool, INIT_TRASH_MAILBOX_COUNT);
	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (array_is_empty(&ns->set->mailboxes))
			continue;

		array_foreach_elem(&ns->set->mailboxes, box_name) {
			if (trash_try_mailbox(ns, box_name, &error) < 0) {
				user->error = p_strdup(user->pool, error);
				return -1;
			}
		}
	}

	array_sort(&tuser->trash_boxes, trash_mailbox_priority_cmp);
	return 0;
}

static void
trash_mail_user_created(struct mail_user *user)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);
	struct trash_user *tuser;

	if (quser == NULL) {
		e_error(user->event,
			"trash plugin: quota plugin not initialized");
	} else {
		tuser = p_new(user->pool, struct trash_user, 1);
		MODULE_CONTEXT_SET(user, trash_user_module, tuser);
	}
}

static void
trash_mail_namespaces_created(struct mail_namespace *namespaces)
{
	struct mail_user *user = namespaces->user;
	struct trash_user *tuser = TRASH_USER_CONTEXT(user);
	if (tuser == NULL)
		return;

	if (trash_find_mailboxes(user) == 0) {
		struct quota_user *quser = QUOTA_USER_CONTEXT_REQUIRE(user);
		trash_next_quota_test_alloc =
			quser->quota->test_alloc;
		quser->quota->test_alloc = trash_quota_test_alloc;
	}
}

static struct mail_storage_hooks trash_mail_storage_hooks = {
	.mail_user_created = trash_mail_user_created,
	.mail_namespaces_created = trash_mail_namespaces_created,
};

void trash_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &trash_mail_storage_hooks);
}

void trash_plugin_deinit(void)
{
	mail_storage_hooks_remove(&trash_mail_storage_hooks);
}

const char *trash_plugin_dependencies[] = { "quota", NULL };
