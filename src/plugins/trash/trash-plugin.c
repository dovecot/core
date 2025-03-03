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

struct trash_clean_root {
	struct quota_root *root;
	struct quota_transaction_root_context *ctx;

	unsigned int trash_count;

	uoff_t count_needed, count_expunged;
	uoff_t bytes_needed, bytes_expunged;
};

struct trash_clean_mailbox {
	const struct trash_mailbox *trash;

	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;
	struct mail *mail;

	ARRAY(struct trash_clean_root *) roots;

	bool finished:1;
};

struct trash_clean {
	struct quota_transaction_context *ctx;
	struct trash_user *user;
	struct event *event;

	ARRAY(struct trash_clean_mailbox) boxes;
	ARRAY(struct trash_clean_root) roots;
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
	.plugin_dependency = "lib11_trash_plugin",

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
			       uoff_t size, struct mailbox *expunged_box,
			       uoff_t expunged_size,
			       const struct quota_overrun **overruns_r,
			       const char **error_r);

static void
trash_clean_init(struct trash_clean *tclean,
		 struct quota_transaction_context *ctx)
{
	i_zero(tclean);
	tclean->ctx = ctx;
	tclean->user = TRASH_USER_CONTEXT_REQUIRE(ctx->quota->user);

	tclean->event = event_create(ctx->quota->user->event);
	event_set_append_log_prefix(tclean->event, "trash plugin: ");
}

static void
trash_clean_root_no_trash(struct trash_clean *tclean,
			  struct trash_clean_root *tcroot)
{
	if (tcroot->count_needed > 0) {
		e_debug(tclean->event, "Quota root %s has no trash mailbox "
			"(needed %"PRIu64" messages)",
			quota_root_get_name(tcroot->root),
			tcroot->count_needed);
		return;
	}
	if (tcroot->bytes_needed > 0) {
		e_debug(tclean->event, "Quota root %s has no trash mailbox "
			"(needed %"PRIu64" bytes)",
			quota_root_get_name(tcroot->root),
			tcroot->bytes_needed);
		return;
	}
	i_unreached();
}

static void
trash_clean_root_insufficient(struct trash_clean *tclean,
			      struct trash_clean_root *tcroot)
{
	if (tcroot->count_needed > tcroot->count_expunged) {
		e_debug(tclean->event,
			"Failed to remove enough messages from quota root %s "
			"(needed %"PRIu64" messages, "
			"expunged only %"PRIu64" messages)",
			quota_root_get_name(tcroot->root),
			tcroot->count_needed, tcroot->count_expunged);
		return;
	}
	if (tcroot->bytes_needed > tcroot->bytes_expunged) {
		e_debug(tclean->event,
			"Failed to remove enough messages from quota root %s "
			"(needed %"PRIu64" bytes, "
			"expunged only %"PRIu64" bytes)",
			quota_root_get_name(tcroot->root),
			tcroot->bytes_needed, tcroot->bytes_expunged);
		return;
	}
	i_unreached();
}

static int trash_clean_mailbox_open(struct trash_clean_mailbox *tcbox)
{
	struct mail_search_args *search_args;

	if (tcbox->box == NULL || tcbox->finished)
		return 0;

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

	if (tcbox->finished)
		return 0;

	if (tcbox->mail == NULL) {
		if (tcbox->search_ctx == NULL)
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

static inline bool trash_clean_root_achieved(const struct trash_clean_root *tcroot)
{
	if (tcroot->count_expunged < tcroot->count_needed ||
	    tcroot->bytes_expunged < tcroot->bytes_needed)
		return FALSE;
	return TRUE;
}

static inline bool trash_clean_achieved(struct trash_clean *tclean)
{
	const struct trash_clean_root *tcroot;

	array_foreach(&tclean->roots, tcroot) {
		if (!trash_clean_root_achieved(tcroot))
			return FALSE;
	}
	return TRUE;
}

static int
trash_clean_mailbox_expunge(struct trash_clean_mailbox *tcbox)
{
	struct trash_clean_root *const *tcrootp;
	bool all_roots_achieved;
	uoff_t size;

	if (mail_get_physical_size(tcbox->mail, &size) < 0) {
		/* maybe expunged already? */
		tcbox->mail = NULL;
		return -1;
	}

	mail_expunge(tcbox->mail);

	all_roots_achieved = TRUE;
	array_foreach(&tcbox->roots, tcrootp) {
		struct trash_clean_root *tcroot = *tcrootp;

		if (tcroot->count_expunged < UINT64_MAX)
			tcroot->count_expunged++;
		if (tcroot->bytes_expunged < (UINT64_MAX - size))
			tcroot->bytes_expunged += size;
		else
			tcroot->bytes_expunged = UINT64_MAX;

		if (!trash_clean_root_achieved(tcroot))
			all_roots_achieved = FALSE;
	}

	tcbox->mail = NULL;

	if (!all_roots_achieved)
		return 0;

	tcbox->finished = TRUE;
	return 1;
}

static int
trash_clean_do_execute(struct trash_clean *tclean,
		       const struct quota_overrun *overruns)
{
	struct quota_transaction_context *ctx = tclean->ctx;
	struct trash_user *tuser = tclean->user;
	struct quota_root *const *roots;
	const struct trash_mailbox *trashes;
	unsigned int root_count, trash_count, tcbox_count, i, j;
	struct trash_clean_mailbox *tcbox, *tcboxes;
	struct trash_clean_root *tcroot;
	int ret = 0;

	roots = array_get(&ctx->quota->all_roots, &root_count);
	trashes = array_get(&tuser->trash_boxes, &trash_count);

	/* Collect quota roots that need cleanup */
	t_array_init(&tclean->roots, root_count);
	for (i = 0; i < root_count; i++) {
		const struct quota_overrun *ovrp = overruns;

		tcroot = array_append_space(&tclean->roots);
		tcroot->root = roots[i];
		tcroot->ctx = &ctx->roots[i];

		while (ovrp->root != NULL) {
			if (ovrp->root == roots[i])
				break;
			ovrp++;
		}
		if (ovrp->root == NULL)
			continue;

		/* Need to reduce resource usage within this root by at least
		   these amounts: */
		tcroot->count_needed = ovrp->resource.count;
		tcroot->bytes_needed = ovrp->resource.bytes;
	}

	/* Open trash mailboxes and determine which quota roots apply */
	t_array_init(&tclean->boxes, trash_count);
	for (i = 0; i < trash_count; i++) {
		const struct trash_mailbox *trash = &trashes[i];
		unsigned int visible;

		tcbox = array_append_space(&tclean->boxes);
		tcbox->trash = trash;

		/* Check namespace visibility for all roots before opening the
		   mailbox */
		visible = 0;
		array_foreach_modifiable(&tclean->roots, tcroot) {
			if (tcroot->count_needed == 0 &&
			    tcroot->bytes_needed == 0)
				continue;
			if (array_lsearch_ptr(&tcroot->root->namespaces,
					      trash->ns) != NULL)
				visible++;
		}

		if (visible == 0) {
			/* This trash mailbox is not relevant to the roots that
			   have quota overruns. */
			continue;
		}

		tcbox->box = mailbox_alloc(trash->ns->list, trash->name, 0);
		if (mailbox_open(tcbox->box) < 0)
			return -1;

		t_array_init(&tcbox->roots, visible);
		array_foreach_modifiable(&tclean->roots, tcroot) {
			if (tcroot->count_needed == 0 &&
			    tcroot->bytes_needed == 0)
				continue;
			if (!quota_root_is_visible(tcroot->root, tcbox->box))
				continue;
			tcroot->trash_count++;
			array_append(&tcbox->roots, &tcroot, 1);
		}

		if (array_count(&tcbox->roots) == 0) {
			/* This trash mailbox is (after closer examination) not
			   relevant to the roots that have quota overruns. */
			mailbox_free(&tcbox->box);
			continue;
		}
	}

	/* Fail early when there are quota roots without a trash mailbox that
	   can be cleaned. */
	array_foreach_modifiable(&tclean->roots, tcroot) {
		if (tcroot->count_needed == 0 &&
		    tcroot->bytes_needed == 0)
			continue;
		if (tcroot->trash_count == 0) {
			trash_clean_root_no_trash(tclean, tcroot);
			return 0;
		}
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
			ret = trash_clean_mailbox_expunge(&tcboxes[oldest_idx]);
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
	array_foreach_modifiable(&tclean->roots, tcroot) {
		if (!trash_clean_root_achieved(tcroot)) {
			trash_clean_root_insufficient(tclean, tcroot);
			return 0;
		}
	}

	return 1;
}

static int
trash_clean_execute(struct trash_clean *tclean,
		    const struct quota_overrun *overruns)
{
	struct quota_transaction_context *ctx = tclean->ctx;
	struct event_reason *reason;
	unsigned int tcbox_count, i;
	struct trash_clean_mailbox *tcboxes;
	struct trash_clean_root *tcroot;
	int ret = 0;

	reason = event_reason_begin("trash:clean");

	ret = trash_clean_do_execute(tclean, overruns);

	/* Commit/rollback the cleanups */
	tcboxes = array_get_modifiable(&tclean->boxes, &tcbox_count);
	for (i = 0; i < tcbox_count; i++) {
		struct trash_clean_mailbox *tcbox = &tcboxes[i];

		if (tcbox->box == NULL || tcbox->trans == NULL)
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
	array_foreach_modifiable(&tclean->roots, tcroot) {
		quota_transaction_root_expunged(tcroot->ctx,
						tcroot->count_expunged,
						tcroot->bytes_expunged);
	}
	quota_transaction_update_expunged(ctx);
	return 1;
}

static void trash_clean_deinit(struct trash_clean *tclean)
{
	struct trash_clean_mailbox *tcbox;

	if (array_is_created(&tclean->boxes)) {
		array_foreach_modifiable(&tclean->boxes, tcbox)
			trash_clean_mailbox_close(tcbox);
	}
	event_unref(&tclean->event);
}

static int
trash_try_clean_mails(struct quota_transaction_context *ctx,
		      const struct quota_overrun *overruns)
{
	int ret;

	i_assert(overruns != NULL);

	T_BEGIN {
		struct trash_clean tclean;

		trash_clean_init(&tclean, ctx);
		ret = trash_clean_execute(&tclean, overruns);
		trash_clean_deinit(&tclean);
	} T_END;

	return ret;
}

static enum quota_alloc_result
trash_quota_test_alloc(struct quota_transaction_context *ctx, uoff_t size,
		       struct mailbox *expunged_box, uoff_t expunged_size,
		       const struct quota_overrun **overruns_r,
		       const char **error_r)
{
	int i;

	for (i = 0; ; i++) {
		const struct quota_overrun *overruns = NULL;
		enum quota_alloc_result ret;

		ret = trash_next_quota_test_alloc(
			ctx, size, expunged_box, expunged_size,
			&overruns, error_r);
		if (overruns_r != NULL)
			*overruns_r = overruns;
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

		/* not enough space. try deleting some from mailbox. */
		if (trash_try_clean_mails(ctx, overruns) <= 0) {
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
