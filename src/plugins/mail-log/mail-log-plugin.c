/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "str-sanitize.h"
#include "imap-util.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "notify-plugin.h"
#include "mail-log-plugin.h"

#include <stdlib.h>

#define MAILBOX_NAME_LOG_LEN 64
#define HEADER_LOG_LEN 80

#define MAIL_LOG_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_log_storage_module)
#define MAIL_LOG_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_log_mail_module)
#define MAIL_LOG_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_log_mailbox_list_module)

enum mail_log_field {
	MAIL_LOG_FIELD_UID	= 0x01,
	MAIL_LOG_FIELD_BOX	= 0x02,
	MAIL_LOG_FIELD_MSGID	= 0x04,
	MAIL_LOG_FIELD_PSIZE	= 0x08,
	MAIL_LOG_FIELD_VSIZE	= 0x10,
	MAIL_LOG_FIELD_FLAGS	= 0x20,
	MAIL_LOG_FIELD_FROM	= 0x40,
	MAIL_LOG_FIELD_SUBJECT	= 0x80
};
#define MAIL_LOG_DEFAULT_FIELDS \
	(MAIL_LOG_FIELD_UID | MAIL_LOG_FIELD_BOX | \
	 MAIL_LOG_FIELD_MSGID | MAIL_LOG_FIELD_PSIZE)

enum mail_log_event {
	MAIL_LOG_EVENT_DELETE		= 0x01,
	MAIL_LOG_EVENT_UNDELETE		= 0x02,
	MAIL_LOG_EVENT_EXPUNGE		= 0x04,
	MAIL_LOG_EVENT_SAVE		= 0x08,
	MAIL_LOG_EVENT_MAILBOX_DELETE	= 0x10,
	MAIL_LOG_EVENT_MAILBOX_RENAME	= 0x20,
	MAIL_LOG_EVENT_FLAG_CHANGE	= 0x40
};
#define MAIL_LOG_DEFAULT_EVENTS \
	(MAIL_LOG_EVENT_DELETE | MAIL_LOG_EVENT_UNDELETE | \
	 MAIL_LOG_EVENT_EXPUNGE | MAIL_LOG_EVENT_SAVE | \
	 MAIL_LOG_EVENT_MAILBOX_DELETE | MAIL_LOG_EVENT_MAILBOX_RENAME)

static const char *field_names[] = {
	"uid",
	"box",
	"msgid",
	"size",
	"vsize",
	"flags",
	"from",
	"subject",
	NULL
};

static const char *event_names[] = {
	"delete",
	"undelete",
	"expunge",
	"save",
	"mailbox_delete",
	"mailbox_rename",
	"flag_change",
	NULL
};

struct mail_log_settings {
	enum mail_log_field fields;
	enum mail_log_event events;
};


struct mail_log_message {
	struct mail_log_message *prev, *next;
	const char *pretext, *text;
};

struct mail_log_mail_txn_context {
	pool_t pool;
	struct mail_log_message *messages, *messages_tail;
};

static struct mail_log_settings mail_log_set;

static enum mail_log_field mail_log_field_find(const char *name)
{
	unsigned int i;

	for (i = 0; field_names[i] != NULL; i++) {
		if (strcmp(name, field_names[i]) == 0)
			return 1 << i;
	}
	return 0;
}

static enum mail_log_event mail_log_event_find(const char *name)
{
	unsigned int i;

	for (i = 0; event_names[i] != NULL; i++) {
		if (strcmp(name, event_names[i]) == 0)
			return 1 << i;
	}
	return 0;
}

static enum mail_log_field mail_log_parse_fields(const char *str)
{
	const char *const *tmp;
	static enum mail_log_field field, fields = 0;

	for (tmp = t_strsplit_spaces(str, ", "); *tmp != NULL; tmp++) {
		field = mail_log_field_find(*tmp);
		if (field == 0)
			i_fatal("Unknown field in mail_log_fields: '%s'", *tmp);
		fields |= field;
	}
	return fields;
}

static enum mail_log_event mail_log_parse_events(const char *str)
{
	const char *const *tmp;
	static enum mail_log_event event, events = 0;

	for (tmp = t_strsplit_spaces(str, ", "); *tmp != NULL; tmp++) {
		event = mail_log_event_find(*tmp);
		if (event == 0)
			i_fatal("Unknown event in mail_log_events: '%s'", *tmp);
		events |= event;
	}
	return events;
}

static void mail_log_read_settings(struct mail_log_settings *set)
{
	const char *str;

	memset(set, 0, sizeof(*set));

	str = getenv("MAIL_LOG_FIELDS");
	set->fields = str == NULL ? MAIL_LOG_DEFAULT_FIELDS :
		mail_log_parse_fields(str);

	str = getenv("MAIL_LOG_EVENTS");
	set->events = str == NULL ? MAIL_LOG_DEFAULT_EVENTS :
		mail_log_parse_events(str);
}

static void mail_log_append_mailbox_name(string_t *str, struct mail *mail)
{
	const char *mailbox_str;

	mailbox_str = mailbox_get_name(mail->box);
	str_printfa(str, "box=%s",
		    str_sanitize(mailbox_str, MAILBOX_NAME_LOG_LEN));
}

static void
mail_log_append_mail_header(string_t *str, struct mail *mail,
			    const char *name, const char *header)
{
	const char *value;

	if (mail_get_first_header(mail, header, &value) <= 0)
		value = "";
	str_printfa(str, "%s=%s", name, str_sanitize(value, HEADER_LOG_LEN));
}

static void
mail_log_append_uid(struct mail_log_mail_txn_context *ctx,
		    struct mail_log_message *msg, string_t *str, uint32_t uid)
{
	if (uid != 0)
		str_printfa(str, "uid=%u", uid);
	else {
		/* we don't know the uid yet, assign it later */
		str_printfa(str, "uid=");
		msg->pretext = p_strdup(ctx->pool, str_c(str));
		str_truncate(str, 0);
	}
}

static void
mail_log_append_mail_message_real(struct mail_log_mail_txn_context *ctx,
				  struct mail *mail, enum mail_log_event event,
				  const char *desc)
{
	struct mail_log_message *msg;
	string_t *text;
	uoff_t size;
	
	msg = p_new(ctx->pool, struct mail_log_message, 1);

	text = t_str_new(128);
	str_append(text, desc);
	str_append(text, ": ");
	if ((mail_log_set.fields & MAIL_LOG_FIELD_BOX) != 0) {
		mail_log_append_mailbox_name(text, mail);
		str_append(text, ", ");
	}
	if ((mail_log_set.fields & MAIL_LOG_FIELD_UID) != 0) {
		if (event == MAIL_LOG_EVENT_SAVE)
			mail_log_append_uid(ctx, msg, text, 0);
		else
			mail_log_append_uid(ctx, msg, text, mail->uid);
		str_append(text, ", ");
	}
	if ((mail_log_set.fields & MAIL_LOG_FIELD_MSGID) != 0) {
		mail_log_append_mail_header(text, mail, "msgid", "Message-ID");
		str_append(text, ", ");
	}
	if ((mail_log_set.fields & MAIL_LOG_FIELD_PSIZE) != 0) {
		if (mail_get_physical_size(mail, &size) == 0)
			str_printfa(text, "size=%"PRIuUOFF_T, size);
		else
			str_printfa(text, "size=error");
		str_append(text, ", ");
	}
	if ((mail_log_set.fields & MAIL_LOG_FIELD_VSIZE) != 0) {
		if (mail_get_virtual_size(mail, &size) == 0)
			str_printfa(text, "vsize=%"PRIuUOFF_T, size);
		else
			str_printfa(text, "vsize=error");
		str_append(text, ", ");
	}
	if ((mail_log_set.fields & MAIL_LOG_FIELD_FROM) != 0) {
		mail_log_append_mail_header(text, mail, "from", "From");
		str_append(text, ", ");
	}
	if ((mail_log_set.fields & MAIL_LOG_FIELD_SUBJECT) != 0) {
		mail_log_append_mail_header(text, mail, "subject", "Subject");
		str_append(text, ", ");
	}
	if ((mail_log_set.fields & MAIL_LOG_FIELD_FLAGS) != 0) {
		str_printfa(text, "flags=(");
		imap_write_flags(text, mail_get_flags(mail),
				 mail_get_keywords(mail));
		str_append(text, "), ");
	}
	str_truncate(text, str_len(text)-2);

	msg->text = p_strdup(ctx->pool, str_c(text));
	msg->prev = ctx->messages_tail;
	ctx->messages_tail = msg;
	if (msg->prev != NULL)
		msg->prev->next = msg;
	if (ctx->messages == NULL)
		ctx->messages = msg;
}

static void
mail_log_append_mail_message(struct mail_log_mail_txn_context *ctx,
			     struct mail *mail, enum mail_log_event event,
			     const char *desc)
{
	if ((mail_log_set.events & event) == 0)
		return;

	T_BEGIN {
		mail_log_append_mail_message_real(ctx, mail, event, desc);
	} T_END;
}

static void *
mail_log_mail_transaction_begin(struct mailbox_transaction_context *t ATTR_UNUSED)
{
	pool_t pool;
	struct mail_log_mail_txn_context *ctx;

	pool = pool_alloconly_create("mail-log", 1024);
	ctx = p_new(pool, struct mail_log_mail_txn_context, 1);
	ctx->pool = pool;
	return ctx;
}

static void mail_log_mail_save(void *txn, struct mail *mail)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;

	mail_log_append_mail_message(ctx, mail, MAIL_LOG_EVENT_SAVE, "save");
}

static void mail_log_mail_copy(void *txn, struct mail *src, struct mail *dst)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;
	const char *desc;

	desc = t_strdup_printf("copy from %s",
			str_sanitize(mailbox_get_name(src->box),
				     MAILBOX_NAME_LOG_LEN));
	mail_log_append_mail_message(ctx, dst, MAIL_LOG_EVENT_SAVE, desc);
}

static void mail_log_mail_expunge(void *txn, struct mail *mail)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;
	
	mail_log_append_mail_message(ctx, mail, MAIL_LOG_EVENT_EXPUNGE,
				     "expunge");
}

static void mail_log_mail_update_flags(void *txn, struct mail *mail,
				       enum mail_flags old_flags)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;
	enum mail_flags new_flags = mail_get_flags(mail);

	if (((old_flags ^ new_flags) & MAIL_DELETED) == 0) {
		mail_log_append_mail_message(ctx, mail,
					     MAIL_LOG_EVENT_FLAG_CHANGE,
					     "flag_change");
	} else if ((old_flags & MAIL_DELETED) == 0) {
		mail_log_append_mail_message(ctx, mail, MAIL_LOG_EVENT_DELETE,
					     "delete");
	} else {
		mail_log_append_mail_message(ctx, mail, MAIL_LOG_EVENT_UNDELETE,
					     "undelete");
	}
}

static void
mail_log_mail_update_keywords(void *txn, struct mail *mail, 
			      const char *const *old_keywords ATTR_UNUSED)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;

	mail_log_append_mail_message(ctx, mail, MAIL_LOG_EVENT_FLAG_CHANGE,
				     "flag_change");
}

static void
mail_log_mail_transaction_commit(void *txn,
				 struct mail_transaction_commit_changes *changes)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;
	struct mail_log_message *msg;
	struct seq_range_iter iter;
	unsigned int n = 0;
	uint32_t uid;
	bool ret;

	seq_range_array_iter_init(&iter, &changes->saved_uids);
	for (msg = ctx->messages; msg != NULL; msg = msg->next) {
		if (msg->pretext == NULL) {
			i_info("%s", msg->text);
		} else {
			ret = seq_range_array_iter_nth(&iter, n++, &uid);
			i_assert(ret);
			i_info("%s%u%s", msg->pretext, uid, msg->text);
		}
	}
	i_assert(!seq_range_array_iter_nth(&iter, n, &uid));

	pool_unref(&ctx->pool);
}

static void mail_log_mail_transaction_rollback(void *txn)
{
	struct mail_log_mail_txn_context *ctx =
		(struct mail_log_mail_txn_context *)txn;

	pool_unref(&ctx->pool);
}

static void
mail_log_mailbox_delete_commit(void *txn ATTR_UNUSED, struct mailbox *box)
{
	if ((mail_log_set.events & MAIL_LOG_EVENT_MAILBOX_DELETE) == 0)
		return;

	i_info("Mailbox deleted: %s",
	       str_sanitize(box->name, MAILBOX_NAME_LOG_LEN));
}

static void
mail_log_mailbox_rename(struct mailbox *src,
			struct mailbox *dest, bool rename_children ATTR_UNUSED)
{
	if ((mail_log_set.events & MAIL_LOG_EVENT_MAILBOX_RENAME) == 0)
		return;

	i_info("Mailbox renamed: %s -> %s",
	       str_sanitize(src->name, MAILBOX_NAME_LOG_LEN),
	       str_sanitize(dest->name, MAILBOX_NAME_LOG_LEN));
}

static const struct notify_vfuncs mail_log_vfuncs = {
	/* mail_transaction_begin */	mail_log_mail_transaction_begin,
	/* mail_save */			mail_log_mail_save,
	/* mail_copy */			mail_log_mail_copy,
	/* mail_expunge */		mail_log_mail_expunge,
	/* mail_update_flags */		mail_log_mail_update_flags,
	/* mail_update_keywords */	mail_log_mail_update_keywords,
	/* mail_transaction_commit */	mail_log_mail_transaction_commit,
	/* mail_transaction_rollback */	mail_log_mail_transaction_rollback,
	/* mailbox_delete_begin */	notify_noop_mailbox_delete_begin,
	/* mailbox_delete_commit */	mail_log_mailbox_delete_commit,
	/* mailbox_delete_rollback */	notify_noop_mailbox_delete_rollback,
	/* mailbox_rename */		mail_log_mailbox_rename,
};

static struct notify_context *mail_log_ctx;

void mail_log_plugin_init(struct module *module ATTR_UNUSED)
{
	mail_log_read_settings(&mail_log_set);
	mail_log_ctx = notify_register(&mail_log_vfuncs);
}

void mail_log_plugin_deinit(void)
{
	notify_unregister(mail_log_ctx);
}

const char *mail_log_plugin_dependencies[] = { "notify", NULL };
