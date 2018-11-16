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
};

struct trash_user {
	union mail_user_module_context module_ctx;

	/* ordered by priority, highest first */
	ARRAY(struct trash_mailbox) trash_boxes;
};

struct trash_clean_mailbox {
	const struct trash_mailbox *trash;

	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;
	struct mail *mail;

	bool finished:1;
};

struct trash_clean {
	struct quota_transaction_context *ctx;
	struct trash_user *user;
	struct event *event;

	ARRAY(struct trash_clean_mailbox) boxes;

	uint64_t bytes_needed, count_needed;
	uint64_t bytes_expunged, count_expunged;
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
static enum quota_alloc_result
(*trash_next_quota_test_alloc)(struct quota_transaction_context *ctx,
			       uoff_t size,
			       const struct quota_overrun **overruns_r,
			       const char **error_r);

static void
trash_clean_init(struct trash_clean *tclean,
		 struct quota_transaction_context *ctx)
{
	i_zero(tclean);
	tclean->ctx = ctx;
	tclean->user = TRASH_USER_CONTEXT_REQUIRE(ctx->quota->user);
}

static int trash_clean_mailbox_open(struct trash_clean_mailbox *tcbox)
{
	const struct trash_mailbox *trash = tcbox->trash;
	struct mail_search_args *search_args;

	tcbox->box = mailbox_alloc(trash->ns->list, trash->name, 0);
	if (mailbox_open(tcbox->box) < 0) {
		mailbox_free(&tcbox->box);
		return 0;
	}

	if (mailbox_sync(tcbox->box, MAILBOX_SYNC_FLAG_FULL_READ) < 0)
		return -1;

	tcbox->trans = mailbox_transaction_begin(tcbox->box, 0, __func__);

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	tcbox->search_ctx = mailbox_search_init(tcbox->trans,
						search_args, NULL,
						MAIL_FETCH_PHYSICAL_SIZE |
						MAIL_FETCH_RECEIVED_DATE, NULL);
	mail_search_args_unref(&search_args);

	return mailbox_search_next(tcbox->search_ctx, &tcbox->mail) ? 1 : 0;
}

static void trash_clean_mailbox_close(struct trash_clean_mailbox *tcbox)
{
	if (tcbox->search_ctx != NULL)
		(void)mailbox_search_deinit(&tcbox->search_ctx);
	if (tcbox->trans != NULL)
		mailbox_transaction_rollback(&tcbox->trans);
	if (tcbox->box != NULL)
		mailbox_free(&tcbox->box);
}

static int
trash_clean_mailbox_get_next(struct trash_clean_mailbox *tcbox,
			     time_t *received_time_r)
{
	int ret;

	if (tcbox->mail == NULL) {
		if (tcbox->box == NULL)
			ret = trash_clean_mailbox_open(tcbox);
		else {
			ret = mailbox_search_next(tcbox->search_ctx,
						  &tcbox->mail) ? 1 : 0;
		}
		if (ret <= 0) {
			*received_time_r = 0;
			return ret;
		}
	}

	if (mail_get_received_date(tcbox->mail, received_time_r) < 0)
		return -1;
	return 1;
}

static inline bool trash_clean_achieved(struct trash_clean *tclean)
{
	if (tclean->bytes_expunged < tclean->bytes_needed &&
	    tclean->count_expunged < tclean->count_needed)
		return FALSE;
       return TRUE;
}

static int
trash_clean_mailbox_expunge(struct trash_clean *tclean,
			    struct trash_clean_mailbox *tcbox)
{
	uoff_t size;

	if (mail_get_physical_size(tcbox->mail, &size) < 0) {
		/* maybe expunged already? */
		tcbox->mail = NULL;
		return -1;
	}

	mail_expunge(tcbox->mail);
	if (tclean->count_expunged < UINT64_MAX)
		tclean->count_expunged++;
	if (tclean->bytes_expunged < (UINT64_MAX - size))
		tclean->bytes_expunged += size;
	else
		tclean->bytes_expunged = UINT64_MAX;

	tcbox->mail = NULL;
	return 0;
}

static int trash_clean_do_execute(struct trash_clean *tclean)
{
	struct quota_transaction_context *ctx = tclean->ctx;
	struct trash_user *tuser = tclean->user;
	const struct trash_mailbox *trashes;
	unsigned int i, j, trash_count, tcbox_count;
	struct trash_clean_mailbox *tcbox, *tcboxes;
	int ret = 0;

	trashes = array_get(&tuser->trash_boxes, &trash_count);

	/* Create trash clean contexts for each trash mailbox. */
	t_array_init(&tclean->boxes, trash_count);
	for (i = 0; i < trash_count; i++) {
		const struct trash_mailbox *trash = &trashes[i];

		tcbox = array_append_space(&tclean->boxes);
		tcbox->trash = trash;
	}

	/* Expunge mails until the required resource usage reductions are
	   achieved. */
	tcboxes = array_get_modifiable(&tclean->boxes, &tcbox_count);
	for (i = 0; i < tcbox_count; ) {
		unsigned int oldest_idx = tcbox_count;
		time_t oldest = (time_t)-1;

		/* expunge oldest mails first in all trash boxes with
		   same priority */
		for (j = i; j < tcbox_count; j++) {
			time_t received = 0;

			if (tcboxes[j].trash->priority !=
			    tcboxes[i].trash->priority)
				break;

			ret = trash_clean_mailbox_get_next(&tcboxes[j],
							   &received);
			if (ret < 0)
				return -1;
			if (ret > 0) {
				if (oldest == (time_t)-1 || received < oldest) {
					oldest = received;
					oldest_idx = j;
				}
			}
		}

		if (oldest_idx < tcbox_count) {
			ret = trash_clean_mailbox_expunge(tclean,
							  &tcboxes[oldest_idx]);
			if (ret < 0)
				continue;
			if (trash_clean_achieved(tclean))
				break;
		} else {
			/* find more mails from next priority's mailbox */
			i = j;
		}
	}

	/* Check whether the required reduction was achieved */
	if (tclean->bytes_expunged < tclean->bytes_needed) {
		e_debug(ctx->quota->user->event,
			"trash plugin: Failed to remove enough messages "
			"(needed %"PRIu64" bytes, "
			 "expunged only %"PRIu64" bytes)",
			tclean->bytes_needed, tclean->bytes_expunged);
		return 0;
	}
	if (tclean->count_expunged < tclean->count_needed) {
		e_debug(ctx->quota->user->event,
			"trash plugin: Failed to remove enough messages "
			"(needed %"PRIu64" messages, "
			 "expunged only %"PRIu64" messages)",
			tclean->count_needed, tclean->count_expunged);
		return 0;
	}

	return 1;
}

static int
trash_clean_execute(struct trash_clean *tclean,
		    uint64_t size_needed, unsigned int count_needed)
{
	struct quota_transaction_context *ctx = tclean->ctx;
	struct event_reason *reason;
	unsigned int i, tcbox_count;
	struct trash_clean_mailbox *tcboxes;
	int ret;

	reason = event_reason_begin("trash:clean");

	tclean->bytes_needed = size_needed;
	tclean->count_needed = count_needed;

	ret = trash_clean_do_execute(tclean);

	/* Commit/rollback the cleanups */
	tcboxes = array_get_modifiable(&tclean->boxes, &tcbox_count);
	for (i = 0; i < tcbox_count; i++) {
		struct trash_clean_mailbox *tcbox = &tcboxes[i];

		if (tcbox->box == NULL)
			continue;

		(void)mailbox_search_deinit(&tcbox->search_ctx);

		if (ret > 0) {
			(void)mailbox_transaction_commit(&tcbox->trans);
			(void)mailbox_sync(tcbox->box, 0);
		} else {
			/* couldn't get enough space, don't expunge anything */
			mailbox_transaction_rollback(&tcbox->trans);
		}
		mailbox_free(&tcbox->box);
	}

	event_reason_end(&reason);

	if (ret <= 0)
		return ret;

	/* Update the resource usage state */
	if ((UINT64_MAX - tclean->count_expunged) < ctx->count_expunged)
		ctx->count_expunged = UINT64_MAX;
	else
		ctx->count_expunged += tclean->count_expunged;

	if ((UINT64_MAX - tclean->bytes_expunged) < ctx->bytes_expunged)
		ctx->bytes_expunged = UINT64_MAX;
	else
		ctx->bytes_expunged += tclean->bytes_expunged;

	return 1;
}

static void trash_clean_deinit(struct trash_clean *tclean)
{
	struct trash_clean_mailbox *tcbox;

	if (array_is_created(&tclean->boxes)) {
		array_foreach_modifiable(&tclean->boxes, tcbox)
			trash_clean_mailbox_close(tcbox);
	}
}

static int
trash_try_clean_mails(struct quota_transaction_context *ctx,
		      uint64_t size_needed, unsigned int count_needed)
{
	int ret;

	T_BEGIN {
		struct trash_clean tclean;

		trash_clean_init(&tclean, ctx);
		ret = trash_clean_execute(&tclean, size_needed, count_needed);
		trash_clean_deinit(&tclean);
	} T_END;

	return ret;
}

static enum quota_alloc_result
trash_quota_test_alloc(struct quota_transaction_context *ctx, uoff_t size,
		       const struct quota_overrun **overruns_r,
		       const char **error_r)
{
	int i;
	uint64_t size_needed = 0;
	unsigned int count_needed = 0;

	for (i = 0; ; i++) {
		enum quota_alloc_result ret;
		ret = trash_next_quota_test_alloc(ctx, size,
						  overruns_r, error_r);
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

		if (ctx->bytes_ceil != UINT64_MAX &&
		    ctx->bytes_ceil < size + ctx->bytes_over)
			size_needed = size + ctx->bytes_over - ctx->bytes_ceil;
		if (ctx->count_ceil != UINT64_MAX &&
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
