/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "str-sanitize.h"
#include "time-util.h"
#include "unichar.h"
#include "var-expand.h"
#include "message-address.h"
#include "smtp-address.h"
#include "lda-settings.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mail-duplicate.h"
#include "mail-deliver.h"

#define DUPLICATE_DB_NAME "lda-dupes"

#define MAIL_DELIVER_USER_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, mail_deliver_user_module)
#define MAIL_DELIVER_STORAGE_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, mail_deliver_storage_module)

struct event_category event_category_mail_delivery = {
	.name = "local-delivery",
};

struct mail_deliver_user {
	union mail_user_module_context module_ctx;
	struct mail_deliver_context *deliver_ctx;
	bool want_storage_id;
};

deliver_mail_func_t *deliver_mail = NULL;

struct mail_deliver_cache {
	bool filled;

	const char *message_id;
	const char *subject;
	const char *from;
	const char *from_envelope;
	const char *storage_id;

	uoff_t psize, vsize;
};

struct mail_deliver_mailbox {
	union mailbox_module_context module_ctx;
};

struct mail_deliver_transaction {
	union mailbox_transaction_module_context module_ctx;

	struct mail_deliver_cache cache;
};

static const char *lda_log_wanted_headers[] = {
	"From", "Message-ID", "Subject",
	NULL
};
static enum mail_fetch_field lda_log_wanted_fetch_fields =
	MAIL_FETCH_PHYSICAL_SIZE | MAIL_FETCH_VIRTUAL_SIZE;
static MODULE_CONTEXT_DEFINE_INIT(mail_deliver_user_module,
				  &mail_user_module_register);
static MODULE_CONTEXT_DEFINE_INIT(mail_deliver_storage_module,
				  &mail_storage_module_register);

static struct message_address *
mail_deliver_get_message_address(struct mail *mail, const char *header)
{
	struct message_address *addr;
	const char *str;

	if (mail_get_first_header(mail, header, &str) <= 0)
		return NULL;
	addr = message_address_parse(pool_datastack_create(),
				     (const unsigned char *)str,
				     strlen(str), 1, 0);
	if (addr == NULL || addr->mailbox == NULL || addr->domain == NULL ||
	    *addr->mailbox == '\0' || *addr->domain == '\0')
		return NULL;
	return addr;
}

const struct smtp_address *
mail_deliver_get_address(struct mail *mail, const char *header)
{
	struct message_address *addr;
	struct smtp_address *smtp_addr;

	addr = mail_deliver_get_message_address(mail, header);
	if (addr == NULL ||
	    smtp_address_create_from_msg_temp(addr, &smtp_addr) < 0)
		return NULL;
	return smtp_addr;
}

static void update_cache(pool_t pool, const char **old_str, const char *new_str)
{
	if (new_str == NULL || new_str[0] == '\0')
		*old_str = NULL;
	else if (*old_str == NULL || strcmp(*old_str, new_str) != 0)
		*old_str = p_strdup(pool, new_str);
}

static void
mail_deliver_log_update_cache(struct mail_deliver_cache *cache, pool_t pool,
			      struct mail *mail)
{
	const char *message_id = NULL, *subject = NULL, *from_envelope = NULL;
	static struct message_address *from_addr;
	const char *from;

	if (cache->filled)
		return;
	cache->filled = TRUE;

	if (mail_get_first_header(mail, "Message-ID", &message_id) > 0)
		message_id = str_sanitize(message_id, 200);
	update_cache(pool, &cache->message_id, message_id);

	if (mail_get_first_header_utf8(mail, "Subject", &subject) > 0)
		subject = str_sanitize(subject, 80);
	update_cache(pool, &cache->subject, subject);

	from_addr = mail_deliver_get_message_address(mail, "From");
	from = (from_addr == NULL ? NULL :
		t_strconcat(from_addr->mailbox, "@", from_addr->domain, NULL));
	update_cache(pool, &cache->from, from);

	if (mail_get_special(mail, MAIL_FETCH_FROM_ENVELOPE, &from_envelope) > 0)
		from_envelope = str_sanitize(from_envelope, 80);
	update_cache(pool, &cache->from_envelope, from_envelope);

	if (mail_get_physical_size(mail, &cache->psize) < 0)
		cache->psize = 0;
	if (mail_get_virtual_size(mail, &cache->vsize) < 0)
		cache->vsize = 0;
}

const struct var_expand_table *
mail_deliver_ctx_get_log_var_expand_table(struct mail_deliver_context *ctx,
					  const char *message)
{
	unsigned int delivery_time_msecs;

	/* If a mail was saved/copied, the cache is already filled and the
	   following call is ignored. Otherwise, only the source mail exists. */
	if (ctx->cache == NULL)
		ctx->cache = p_new(ctx->pool, struct mail_deliver_cache, 1);
	mail_deliver_log_update_cache(ctx->cache, ctx->pool, ctx->src_mail);
	/* This call finishes a mail delivery. With Sieve there may be multiple
	   mail deliveries. */
	ctx->cache->filled = FALSE;

	io_loop_time_refresh();
	delivery_time_msecs = timeval_diff_msecs(&ioloop_timeval,
						 &ctx->delivery_time_started);

	const struct var_expand_table stack_tab[] = {
		{ '$', message, NULL },
		{ 'm', ctx->cache->message_id != NULL ?
		       ctx->cache->message_id : "unspecified", "msgid" },
		{ 's', ctx->cache->subject, "subject" },
		{ 'f', ctx->cache->from, "from" },
		{ 'e', ctx->cache->from_envelope, "from_envelope" },
		{ 'p', dec2str(ctx->cache->psize), "size" },
		{ 'w', dec2str(ctx->cache->vsize), "vsize" },
		{ '\0', dec2str(delivery_time_msecs), "delivery_time" },
		{ '\0', dec2str(ctx->session_time_msecs), "session_time" },
		{ '\0', smtp_address_encode(ctx->rcpt_params.orcpt.addr), "to_envelope" },
		{ '\0', ctx->cache->storage_id, "storage_id" },
		{ '\0', NULL, NULL }
	};
	return p_memdup(unsafe_data_stack_pool, stack_tab, sizeof(stack_tab));
}

void mail_deliver_log(struct mail_deliver_context *ctx, const char *fmt, ...)
{
	va_list args;
	string_t *str;
	const struct var_expand_table *tab;
	const char *msg, *error;

	if (*ctx->set->deliver_log_format == '\0')
		return;

	va_start(args, fmt);
	msg = t_strdup_vprintf(fmt, args);

	str = t_str_new(256);
	tab = mail_deliver_ctx_get_log_var_expand_table(ctx, msg);
	if (var_expand(str, ctx->set->deliver_log_format, tab, &error) <= 0) {
		i_error("Failed to expand deliver_log_format=%s: %s",
			ctx->set->deliver_log_format, error);
	}

	i_info("%s", str_c(str));
	va_end(args);
}

struct mail_deliver_session *mail_deliver_session_init(void)
{
	struct mail_deliver_session *session;
	pool_t pool;

	pool = pool_alloconly_create("mail deliver session", 1024);
	session = p_new(pool, struct mail_deliver_session, 1);
	session->pool = pool;
	return session;
}

void mail_deliver_session_deinit(struct mail_deliver_session **_session)
{
	struct mail_deliver_session *session = *_session;

	*_session = NULL;
	pool_unref(&session->pool);
}

int mail_deliver_save_open(struct mail_deliver_save_open_context *ctx,
			   const char *name, struct mailbox **box_r,
			   enum mail_error *error_r, const char **error_str_r)
{
	struct mailbox *box;
	enum mailbox_flags flags = 0;

	*box_r = NULL;
	*error_r = MAIL_ERROR_NONE;
	*error_str_r = NULL;

	if (!uni_utf8_str_is_valid(name)) {
		*error_str_r = "Mailbox name not valid UTF-8";
		*error_r = MAIL_ERROR_PARAMS;
		return -1;
	}

	if (ctx->lda_mailbox_autocreate)
		flags |= MAILBOX_FLAG_AUTO_CREATE;
	if (ctx->lda_mailbox_autosubscribe)
		flags |= MAILBOX_FLAG_AUTO_SUBSCRIBE;
	*box_r = box = mailbox_alloc_delivery(ctx->user, name, flags);

	if (mailbox_open(box) == 0)
		return 0;
	*error_str_r = mailbox_get_last_internal_error(box, error_r);
	return -1;
}

static bool mail_deliver_check_duplicate(struct mail_deliver_session *session,
					 struct mailbox *box)
{
	struct mailbox_metadata metadata;
	const guid_128_t *guid;

	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) < 0) {
		/* just play it safe and assume a duplicate */
		return TRUE;
	}

	/* there shouldn't be all that many recipients,
	   so just do a linear search */
	if (!array_is_created(&session->inbox_guids))
		p_array_init(&session->inbox_guids, session->pool, 8);
	array_foreach(&session->inbox_guids, guid) {
		if (memcmp(metadata.guid, *guid, sizeof(metadata.guid)) == 0)
			return TRUE;
	}
	array_push_back(&session->inbox_guids, &metadata.guid);
	return FALSE;
}

void mail_deliver_deduplicate_guid_if_needed(struct mail_deliver_session *session,
					     struct mail_save_context *save_ctx)
{
	struct mailbox_transaction_context *trans =
		mailbox_save_get_transaction(save_ctx);
	struct mailbox *box = mailbox_transaction_get_mailbox(trans);
	guid_128_t guid;

	if (strcmp(mailbox_get_name(box), "INBOX") != 0)
		return;

	/* avoid storing duplicate GUIDs to delivered mails to INBOX. this
	   happens if mail is delivered to same user multiple times within a
	   session. the problem with this is that if GUIDs are used as POP3
	   UIDLs, some clients can't handle the duplicates well. */
	if (mail_deliver_check_duplicate(session, box)) {
		guid_128_generate(guid);
		mailbox_save_set_guid(save_ctx, guid_128_to_string(guid));
	}
}

void mail_deliver_init(struct mail_deliver_context *ctx,
		       struct mail_deliver_input *input)
{
	i_zero(ctx);
	ctx->set = input->set;
	ctx->smtp_set = input->smtp_set;

	ctx->session = input->session;
	ctx->pool = input->session->pool;
	pool_ref(ctx->pool);

	ctx->session_time_msecs = input->session_time_msecs;
	ctx->delivery_time_started = input->delivery_time_started;
	ctx->session_id = p_strdup(ctx->pool, input->session_id);
	ctx->src_mail = input->src_mail;
	ctx->save_dest_mail = input->save_dest_mail;

	ctx->mail_from = smtp_address_clone(ctx->pool, input->mail_from);
	smtp_params_mail_copy(ctx->pool, &ctx->mail_params,
			      &input->mail_params);
	ctx->rcpt_to = smtp_address_clone(ctx->pool, input->rcpt_to);
	smtp_params_rcpt_copy(ctx->pool, &ctx->rcpt_params,
			      &input->rcpt_params);
	ctx->rcpt_user = input->rcpt_user;
	ctx->rcpt_default_mailbox = p_strdup(ctx->pool,
					     input->rcpt_default_mailbox);

	ctx->event = event_create(input->event_parent);
	event_add_category(ctx->event, &event_category_mail_delivery);

	if (ctx->rcpt_to != NULL) {
		event_add_str(ctx->event, "rcpt_to",
			      smtp_address_encode(ctx->rcpt_to));
	}
	smtp_params_rcpt_add_to_event(&ctx->rcpt_params, ctx->event);
}

void mail_deliver_deinit(struct mail_deliver_context *ctx)
{
	event_unref(&ctx->event);
	pool_unref(&ctx->pool);
}

static struct mail *
mail_deliver_open_mail(struct mailbox *box, uint32_t uid,
		       enum mail_fetch_field wanted_fields,
		       struct mailbox_transaction_context **trans_r)
{
	struct mailbox_transaction_context *t;
	struct mail *mail;

	*trans_r = NULL;

	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FAST) < 0)
		return NULL;

	t = mailbox_transaction_begin(box, 0, __func__);
	mail = mail_alloc(t, wanted_fields, NULL);

	if (!mail_set_uid(mail, uid)) {
		mail_free(&mail);
		mailbox_transaction_rollback(&t);
	}
	*trans_r = t;
	return mail;
}

int mail_deliver_save(struct mail_deliver_context *ctx, const char *mailbox,
		      enum mail_flags flags, const char *const *keywords,
		      struct mail_storage **storage_r)
{
	struct mail_deliver_save_open_context open_ctx;
	struct mailbox *box;
	enum mailbox_transaction_flags trans_flags;
	struct mailbox_transaction_context *t;
	struct mail_save_context *save_ctx;
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct mail_keywords *kw;
	struct mail *dest_mail;
	enum mail_error error;
	const char *mailbox_name, *errstr, *guid;
	struct mail_transaction_commit_changes changes;
	bool default_save;
	int ret = 0;

	i_assert(ctx->dest_mail == NULL);

	default_save = strcmp(mailbox, ctx->rcpt_default_mailbox) == 0;
	if (default_save)
		ctx->tried_default_save = TRUE;

	i_zero(&open_ctx);
	open_ctx.user = ctx->rcpt_user;
	open_ctx.lda_mailbox_autocreate = ctx->set->lda_mailbox_autocreate;
	open_ctx.lda_mailbox_autosubscribe = ctx->set->lda_mailbox_autosubscribe;

	mailbox_name = str_sanitize(mailbox, 80);
	if (mail_deliver_save_open(&open_ctx, mailbox, &box,
				   &error, &errstr) < 0) {
		if (box != NULL) {
			*storage_r = mailbox_get_storage(box);
			mailbox_free(&box);
		}
		mail_deliver_log(ctx, "save failed to open mailbox %s: %s",
				 mailbox_name, errstr);
		return -1;
	}
	*storage_r = mailbox_get_storage(box);

	trans_flags = MAILBOX_TRANSACTION_FLAG_EXTERNAL;
	if (ctx->save_dest_mail)
		trans_flags |= MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS;
	t = mailbox_transaction_begin(box, trans_flags, __func__);

	kw = str_array_length(keywords) == 0 ? NULL :
		mailbox_keywords_create_valid(box, keywords);
	save_ctx = mailbox_save_alloc(t);
	if (ctx->mail_from != NULL) {
		mailbox_save_set_from_envelope(save_ctx,
			smtp_address_encode(ctx->mail_from));
	}
	mailbox_save_set_flags(save_ctx, flags, kw);

	headers_ctx = mailbox_header_lookup_init(box, lda_log_wanted_headers);
	dest_mail = mailbox_save_get_dest_mail(save_ctx);
	mail_add_temp_wanted_fields(dest_mail, lda_log_wanted_fetch_fields, NULL);
	mailbox_header_lookup_unref(&headers_ctx);
	mail_deliver_deduplicate_guid_if_needed(ctx->session, save_ctx);

	if (mailbox_save_using_mail(&save_ctx, ctx->src_mail) < 0)
		ret = -1;
	if (kw != NULL)
		mailbox_keywords_unref(&kw);

	if (ret < 0)
		mailbox_transaction_rollback(&t);
	else
		ret = mailbox_transaction_commit_get_changes(&t, &changes);

	if (ret == 0) {
		ctx->saved_mail = TRUE;
		if (ctx->save_dest_mail) {
			/* copying needs the message body. with maildir we also
			   need to get the GUID in case the message gets
			   expunged. get these early so the copying won't fail
			   later on. */
			i_assert(array_count(&changes.saved_uids) == 1);
			const struct seq_range *range =
				array_front(&changes.saved_uids);
			i_assert(range->seq1 == range->seq2);
			ctx->dest_mail = mail_deliver_open_mail(box, range->seq1,
				MAIL_FETCH_STREAM_BODY | MAIL_FETCH_GUID, &t);
			if (ctx->dest_mail == NULL) {
				i_assert(t == NULL);
			} else if (mail_get_special(ctx->dest_mail, MAIL_FETCH_GUID, &guid) < 0) {
				mail_free(&ctx->dest_mail);
				mailbox_transaction_rollback(&t);
			}
		}
		mail_deliver_log(ctx, "saved mail to %s", mailbox_name);
		pool_unref(&changes.pool);
	} else {
		mail_deliver_log(ctx, "save failed to %s: %s", mailbox_name,
			mail_storage_get_last_internal_error(*storage_r, &error));
	}

	if (ctx->dest_mail == NULL)
		mailbox_free(&box);
	return ret;
}

const struct smtp_address *
mail_deliver_get_return_address(struct mail_deliver_context *ctx)
{
	struct message_address *addr;
	struct smtp_address *smtp_addr;
	const char *path;
	int ret;

	if (!smtp_address_isnull(ctx->mail_from))
		return ctx->mail_from;

	if ((ret=mail_get_first_header(ctx->src_mail,
				       "Return-Path", &path)) <= 0) {
		if (ret < 0) {
			struct mailbox *box = ctx->src_mail->box;
			i_warning("Failed read return-path header: %s",
				mailbox_get_last_internal_error(box, NULL));
		}
		return NULL;
	}
	if (message_address_parse_path(pool_datastack_create(),
				       (const unsigned char *)path,
				       strlen(path), &addr) < 0 ||
	    smtp_address_create_from_msg(ctx->pool, addr, &smtp_addr) < 0) {
		i_warning("Failed to parse return-path header");
		return NULL;
	}
	return smtp_addr;
}

const char *mail_deliver_get_new_message_id(struct mail_deliver_context *ctx)
{
	static int count = 0;
	struct mail_user *user = ctx->rcpt_user;
	const struct mail_storage_settings *mail_set =
		mail_user_set_get_storage_set(user);

	return t_strdup_printf("<dovecot-%s-%s-%d@%s>",
			       dec2str(ioloop_timeval.tv_sec),
			       dec2str(ioloop_timeval.tv_usec),
			       count++, mail_set->hostname);
}

static bool mail_deliver_is_tempfailed(struct mail_deliver_context *ctx,
				       struct mail_storage *storage)
{
	enum mail_error error;

	if (ctx->tempfail_error != NULL)
		return TRUE;
	if (storage != NULL) {
		(void)mail_storage_get_last_error(storage, &error);
		return error == MAIL_ERROR_TEMP;
	}
	return FALSE;
}

static int
mail_do_deliver(struct mail_deliver_context *ctx,
		struct mail_storage **storage_r)
{
	int ret;

	*storage_r = NULL;
	if (deliver_mail == NULL)
		ret = -1;
	else {
		ctx->dup_db = mail_duplicate_db_init(ctx->rcpt_user,
						     DUPLICATE_DB_NAME);
		if (deliver_mail(ctx, storage_r) <= 0) {
			/* if message was saved, don't bounce it even though
			   the script failed later. */
			ret = ctx->saved_mail ? 0 : -1;
		} else {
			/* success. message may or may not have been saved. */
			ret = 0;
		}
		mail_duplicate_db_deinit(&ctx->dup_db);
		if (ret < 0 && mail_deliver_is_tempfailed(ctx, *storage_r))
			return -1;
	}

	if (ret < 0 && !ctx->tried_default_save) {
		/* plugins didn't handle this. save into the default mailbox. */
		ret = mail_deliver_save(ctx, ctx->rcpt_default_mailbox, 0, NULL,
					storage_r);
		if (ret < 0 && mail_deliver_is_tempfailed(ctx, *storage_r))
			return -1;
	}
	if (ret < 0 && strcasecmp(ctx->rcpt_default_mailbox, "INBOX") != 0) {
		/* still didn't work. try once more to save it
		   to INBOX. */
		ret = mail_deliver_save(ctx, "INBOX", 0, NULL, storage_r);
	}
	return ret;
}

int mail_deliver(struct mail_deliver_context *ctx,
		 struct mail_storage **storage_r)
{
	struct mail_deliver_user *muser =
		MAIL_DELIVER_USER_CONTEXT(ctx->rcpt_user);
	int ret;

	i_assert(muser->deliver_ctx == NULL);

	muser->want_storage_id =
		var_has_key(ctx->set->deliver_log_format, '\0', "storage_id");

	muser->deliver_ctx = ctx;

	ret = mail_do_deliver(ctx, storage_r);

	muser->deliver_ctx = NULL;

	return ret;
}

deliver_mail_func_t *mail_deliver_hook_set(deliver_mail_func_t *new_hook)
{
	deliver_mail_func_t *old_hook = deliver_mail;

	deliver_mail = new_hook;
	return old_hook;
}

static int mail_deliver_save_finish(struct mail_save_context *ctx)
{
	struct mailbox *box = ctx->transaction->box;
	struct mail_deliver_mailbox *mbox = MAIL_DELIVER_STORAGE_CONTEXT(box);
	struct mail_deliver_user *muser =
		MAIL_DELIVER_USER_CONTEXT(box->storage->user);
	struct mail_deliver_transaction *dt =
		MAIL_DELIVER_STORAGE_CONTEXT(ctx->transaction);

	if (mbox->module_ctx.super.save_finish(ctx) < 0)
		return -1;

	/* initialize most of the fields from dest_mail */
	mail_deliver_log_update_cache(&dt->cache, muser->deliver_ctx->pool,
				      ctx->dest_mail);
	return 0;
}

static int mail_deliver_copy(struct mail_save_context *ctx, struct mail *mail)
{
	struct mailbox *box = ctx->transaction->box;
	struct mail_deliver_mailbox *mbox = MAIL_DELIVER_STORAGE_CONTEXT(box);
	struct mail_deliver_user *muser =
		MAIL_DELIVER_USER_CONTEXT(box->storage->user);
	struct mail_deliver_transaction *dt =
		MAIL_DELIVER_STORAGE_CONTEXT(ctx->transaction);

	if (mbox->module_ctx.super.copy(ctx, mail) < 0)
		return -1;

	/* initialize most of the fields from dest_mail */
	mail_deliver_log_update_cache(&dt->cache, muser->deliver_ctx->pool,
				      ctx->dest_mail);
	return 0;
}

static void
mail_deliver_cache_update_post_commit(struct mailbox *orig_box, uint32_t uid)
{
	struct mail_deliver_user *muser =
		MAIL_DELIVER_USER_CONTEXT(orig_box->storage->user);
	struct mailbox *box;
	struct mailbox_transaction_context *t;
	struct mail *mail;
	const char *storage_id;

	if (!muser->want_storage_id)
		return;

	/* getting storage_id requires a whole new mailbox view that is
	   synced, so it'll contain the newly written mail. this is racy, so
	   it's possible another process has already deleted the mail. */
	box = mailbox_alloc(orig_box->list, orig_box->vname, 0);
	mailbox_set_reason(box, "lib-lda storage-id");

	mail = mail_deliver_open_mail(box, uid, MAIL_FETCH_STORAGE_ID, &t);
	if (mail != NULL) {
		if (mail_get_special(mail, MAIL_FETCH_STORAGE_ID, &storage_id) < 0 ||
		    storage_id[0] == '\0')
			storage_id = NULL;
		muser->deliver_ctx->cache->storage_id =
			p_strdup(muser->deliver_ctx->pool, storage_id);
		mail_free(&mail);
		(void)mailbox_transaction_commit(&t);
	} else {
		muser->deliver_ctx->cache->storage_id = NULL;
	}
	mailbox_free(&box);
}

static struct mailbox_transaction_context *
mail_deliver_transaction_begin(struct mailbox *box,
			       enum mailbox_transaction_flags flags,
			       const char *reason)
{
	struct mail_deliver_mailbox *mbox = MAIL_DELIVER_STORAGE_CONTEXT(box);
	struct mail_deliver_user *muser =
		MAIL_DELIVER_USER_CONTEXT(box->storage->user);
	struct mailbox_transaction_context *t;
	struct mail_deliver_transaction *dt;

	i_assert(muser->deliver_ctx != NULL);

	t = mbox->module_ctx.super.transaction_begin(box, flags, reason);
	dt = p_new(muser->deliver_ctx->pool, struct mail_deliver_transaction, 1);

	MODULE_CONTEXT_SET(t, mail_deliver_storage_module, dt);
	return t;
}

static int
mail_deliver_transaction_commit(struct mailbox_transaction_context *ctx,
				struct mail_transaction_commit_changes *changes_r)
{
	struct mailbox *box = ctx->box;
	struct mail_deliver_mailbox *mbox = MAIL_DELIVER_STORAGE_CONTEXT(box);
	struct mail_deliver_transaction *dt = MAIL_DELIVER_STORAGE_CONTEXT(ctx);
	struct mail_deliver_user *muser =
		MAIL_DELIVER_USER_CONTEXT(box->storage->user);

	i_assert(muser->deliver_ctx != NULL);

	/* sieve creates multiple transactions, saves the mails and
	   then commits all of them at the end. we'll need to keep
	   switching the deliver_ctx->cache for each commit.

	   we also want to do this only for commits generated by sieve.
	   other plugins or storage backends may be creating transactions as
	   well, which we need to ignore. */
	if ((box->flags & MAILBOX_FLAG_POST_SESSION) != 0)
		muser->deliver_ctx->cache = &dt->cache;

	if (mbox->module_ctx.super.transaction_commit(ctx, changes_r) < 0)
		return -1;

	if (array_count(&changes_r->saved_uids) > 0) {
		const struct seq_range *range =
			array_front(&changes_r->saved_uids);

		mail_deliver_cache_update_post_commit(box, range->seq1);
	}
	return 0;
}

static void mail_deliver_mail_user_created(struct mail_user *user)
{
	struct mail_deliver_user *muser;

	muser = p_new(user->pool, struct mail_deliver_user, 1);
	MODULE_CONTEXT_SET(user, mail_deliver_user_module, muser);
}

static void mail_deliver_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct mail_deliver_mailbox *mbox;
	struct mail_deliver_user *muser =
		MAIL_DELIVER_USER_CONTEXT(box->storage->user);

	/* we are doing something other than lda/lmtp delivery
	   and should not be involved */
	if (muser->deliver_ctx == NULL)
		return;

	if ((box->flags & MAILBOX_FLAG_POST_SESSION) != 0)
		mailbox_set_reason(box, "lib-lda delivery");

	mbox = p_new(box->pool, struct mail_deliver_mailbox, 1);
	mbox->module_ctx.super = *v;
	box->vlast = &mbox->module_ctx.super;
	v->save_finish = mail_deliver_save_finish;
	v->copy = mail_deliver_copy;
	v->transaction_begin = mail_deliver_transaction_begin;
	v->transaction_commit = mail_deliver_transaction_commit;

	MODULE_CONTEXT_SET(box, mail_deliver_storage_module, mbox);
 }

static struct mail_storage_hooks mail_deliver_hooks = {
	.mail_user_created = mail_deliver_mail_user_created,
	.mailbox_allocated = mail_deliver_mailbox_allocated
};

void mail_deliver_hooks_init(void)
{
	mail_storage_hooks_add_internal(&mail_deliver_hooks);
}
