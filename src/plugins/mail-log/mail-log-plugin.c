/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "str-sanitize.h"
#include "imap-util.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "mail-user.h"
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
#define MAIL_LOG_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_log_mail_user_module)

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
	MAIL_LOG_EVENT_COPY		= 0x08,
	MAIL_LOG_EVENT_MAILBOX_DELETE	= 0x10,
	MAIL_LOG_EVENT_MAILBOX_RENAME	= 0x20,
	MAIL_LOG_EVENT_FLAG_CHANGE	= 0x40,
	MAIL_LOG_EVENT_APPEND		= 0x80
};
#define MAIL_LOG_DEFAULT_EVENTS \
	(MAIL_LOG_EVENT_DELETE | MAIL_LOG_EVENT_UNDELETE | \
	 MAIL_LOG_EVENT_EXPUNGE | MAIL_LOG_EVENT_COPY | \
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
	"copy",
	"mailbox_delete",
	"mailbox_rename",
	"flag_change",
	"append",
	NULL
};

struct mail_log_user {
	union mail_user_module_context module_ctx;

	enum mail_log_field fields;
	enum mail_log_event events;

	unsigned int group_events:1;
};

struct mail_log_group_changes {
	enum mail_log_event event;
	const char *data;

	ARRAY_TYPE(seq_range) uids;
	uoff_t psize_total, vsize_total;
};

struct mail_log_transaction_context {
	union mailbox_transaction_module_context module_ctx;
	pool_t pool;
	struct mail *tmp_mail;

	ARRAY_DEFINE(group_changes, struct mail_log_group_changes);

	unsigned int changes;
};

const char *mail_log_plugin_version = PACKAGE_VERSION;

static void (*mail_log_next_hook_mail_storage_created)
	(struct mail_storage *storage);
static void (*mail_log_next_hook_mailbox_list_created)
	(struct mailbox_list *list);
static void (*mail_log_next_hook_mail_user_created)(struct mail_user *user);

static MODULE_CONTEXT_DEFINE_INIT(mail_log_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(mail_log_mail_module, &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(mail_log_mailbox_list_module,
				  &mailbox_list_module_register);
static MODULE_CONTEXT_DEFINE_INIT(mail_log_mail_user_module,
				  &mail_user_module_register);

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

static const char *mail_log_event_get_name(enum mail_log_event event)
{
	unsigned int i;

	for (i = 0; event_names[i] != NULL; i++) {
		if ((unsigned)event == (unsigned)(1 << i))
			return event_names[i];
	}
	i_unreached();
	return NULL;
}

static struct mail_log_group_changes *
mail_log_action_get_group(struct mail_log_transaction_context *lt,
			  enum mail_log_event event, const char *data)
{
	struct mail_log_group_changes *group;
	unsigned int i, count;

	if (!array_is_created(&lt->group_changes))
		p_array_init(&lt->group_changes, lt->pool, 8);

	group = array_get_modifiable(&lt->group_changes, &count);
	for (i = 0; i < count; i++) {
		if (group[i].event == event &&
		    null_strcmp(data, group[i].data) == 0)
			return &group[i];
	}

	group = array_append_space(&lt->group_changes);
	group->event = event;
	group->data = p_strdup(lt->pool, data);
	return group;
}

static void
mail_log_action_add_group(struct mail_log_transaction_context *lt,
			  struct mail *mail, enum mail_log_event event,
			  const char *data)
{
	struct mail_log_user *muser =
		MAIL_LOG_USER_CONTEXT(mail->box->storage->user);
	struct mail_log_group_changes *group;
	uoff_t size;

	group = mail_log_action_get_group(lt, event, data);

	if ((muser->fields & MAIL_LOG_FIELD_UID) != 0) {
		if (!array_is_created(&group->uids))
			p_array_init(&group->uids, lt->pool, 32);
		seq_range_array_add(&group->uids, 0, mail->uid);
	}

	if ((muser->fields & MAIL_LOG_FIELD_PSIZE) != 0 &&
	    (event & (MAIL_LOG_EVENT_EXPUNGE | MAIL_LOG_EVENT_COPY)) != 0) {
		if (mail_get_physical_size(mail, &size) == 0)
			group->psize_total += size;
	}

	if ((muser->fields & MAIL_LOG_FIELD_VSIZE) != 0 &&
	    (event & (MAIL_LOG_EVENT_EXPUNGE | MAIL_LOG_EVENT_COPY)) != 0) {
		if (mail_get_virtual_size(mail, &size) == 0)
			group->vsize_total += size;
	}
}

static void mail_log_append_mailbox_name(string_t *str, struct mailbox *box)
{
	const char *mailbox_str;

	/* most operations are for INBOX, and POP3 has only INBOX,
	   so don't add it. */
	mailbox_str = mailbox_get_vname(box);
	if (strcmp(mailbox_str, "INBOX") != 0) {
		str_printfa(str, "box=%s, ",
			    str_sanitize(mailbox_str, MAILBOX_NAME_LOG_LEN));
	}
}

static void
mail_log_group(struct mailbox *box, const struct mail_log_group_changes *group)
{
	struct mail_log_user *muser =
		MAIL_LOG_USER_CONTEXT(box->storage->user);
	const struct seq_range *range;
	unsigned int i, count;
	string_t *str;
	
	str = t_str_new(128);
	str_printfa(str, "%s: ", mail_log_event_get_name(group->event));

	if ((muser->fields & MAIL_LOG_FIELD_UID) != 0 &&
	    array_is_created(&group->uids)) {
		str_append(str, "uids=");

		range = array_get(&group->uids, &count);
		for (i = 0; i < count; i++) {
			if (i != 0)
				str_append_c(str, ',');

			str_printfa(str, "%u", range[i].seq1);
			if (range[i].seq1 != range[i].seq2)
				str_printfa(str, "-%u", range[i].seq2);
		}
		str_append(str, ", ");
	}

	if ((muser->fields & MAIL_LOG_FIELD_BOX) != 0)
		mail_log_append_mailbox_name(str, box);

	if (group->event == MAIL_LOG_EVENT_COPY)
		str_printfa(str, "dest=%s, ", group->data);

	if (group->psize_total != 0)
		str_printfa(str, "size=%"PRIuUOFF_T", ", group->psize_total);
	if (group->vsize_total != 0)
		str_printfa(str, "size=%"PRIuUOFF_T", ", group->vsize_total);
	str_truncate(str, str_len(str)-2);

	i_info("%s", str_c(str));
}

static void
mail_log_group_changes(struct mailbox *box,
		       struct mail_log_transaction_context *lt)
{
	const struct mail_log_group_changes *group;
	unsigned int i, count;

	group = array_get(&lt->group_changes, &count);
	for (i = 0; i < count; i++) {
		T_BEGIN {
			mail_log_group(box, &group[i]);
		} T_END;
	}
}

static void mail_log_add_hdr(struct mail *mail, string_t *str,
			     const char *name, const char *header)
{
	const char *value;

	if (mail_get_first_header(mail, header, &value) <= 0)
		value = "";
	str_printfa(str, "%s=%s, ", name, str_sanitize(value, HEADER_LOG_LEN));
}

static void mail_log_action(struct mailbox_transaction_context *dest_trans,
			    struct mail *mail, enum mail_log_event event,
			    const char *data)
{
	struct mail_log_transaction_context *lt = MAIL_LOG_CONTEXT(dest_trans);
	struct mail_log_user *muser =
		MAIL_LOG_USER_CONTEXT(mail->box->storage->user);
	uoff_t size;
	string_t *str;

	if ((muser->events & event) == 0)
		return;

	lt->changes++;

	if (muser->group_events) {
		mail_log_action_add_group(lt, mail, event, data);
		return;
	}

	str = t_str_new(128);
	str_printfa(str, "%s: ", mail_log_event_get_name(event));

	if ((muser->fields & MAIL_LOG_FIELD_UID) != 0 && mail->uid != 0)
		str_printfa(str, "uid=%u, ", mail->uid);

	if ((muser->fields & MAIL_LOG_FIELD_BOX) != 0)
		mail_log_append_mailbox_name(str, mail->box);
	if ((muser->fields & MAIL_LOG_FIELD_FLAGS) != 0) {
		str_printfa(str, "flags=(");
		imap_write_flags(str, mail_get_flags(mail),
				 mail_get_keywords(mail));
		str_append(str, "), ");
	}
	if (event == MAIL_LOG_EVENT_COPY)
		str_printfa(str, "dest=%s, ", data);

	if ((muser->fields & MAIL_LOG_FIELD_MSGID) != 0)
		mail_log_add_hdr(mail, str, "msgid", "Message-ID");
	if ((muser->fields & MAIL_LOG_FIELD_FROM) != 0)
		mail_log_add_hdr(mail, str, "from", "From");
	if ((muser->fields & MAIL_LOG_FIELD_SUBJECT) != 0)
		mail_log_add_hdr(mail, str, "subject", "Subject");

	if ((muser->fields & MAIL_LOG_FIELD_PSIZE) != 0 &&
	    (event & (MAIL_LOG_EVENT_EXPUNGE | MAIL_LOG_EVENT_COPY)) != 0) {
		if (mail_get_physical_size(mail, &size) == 0)
			str_printfa(str, "size=%"PRIuUOFF_T", ", size);
	}
	if ((muser->fields & MAIL_LOG_FIELD_VSIZE) != 0 &&
	    (event & (MAIL_LOG_EVENT_EXPUNGE | MAIL_LOG_EVENT_COPY)) != 0) {
		if (mail_get_virtual_size(mail, &size) == 0)
			str_printfa(str, "vsize=%"PRIuUOFF_T", ", size);
	}
	str_truncate(str, str_len(str)-2);

	i_info("%s", str_c(str));
}

static void mail_log_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *lmail = MAIL_LOG_MAIL_CONTEXT(mail);

	T_BEGIN {
		mail_log_action(_mail->transaction, _mail,
				MAIL_LOG_EVENT_EXPUNGE, NULL);
	} T_END;
	lmail->super.expunge(_mail);
}

static void
mail_log_mail_update_flags(struct mail *_mail, enum modify_type modify_type,
			   enum mail_flags flags)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *lmail = MAIL_LOG_MAIL_CONTEXT(mail);
	enum mail_flags old_flags, new_flags;

	old_flags = mail_get_flags(_mail);
	lmail->super.update_flags(_mail, modify_type, flags);

	new_flags = old_flags;
	switch (modify_type) {
	case MODIFY_ADD:
		new_flags |= flags;
		break;
	case MODIFY_REMOVE:
		new_flags &= ~flags;
		break;
	case MODIFY_REPLACE:
		new_flags = flags;
		break;
	}

	if (((old_flags ^ new_flags) & MAIL_DELETED) != 0) T_BEGIN {
		mail_log_action(_mail->transaction, _mail,
				(new_flags & MAIL_DELETED) != 0 ?
				MAIL_LOG_EVENT_DELETE :
				MAIL_LOG_EVENT_UNDELETE, NULL);
	} T_END;

	if ((old_flags & ~MAIL_DELETED) != (new_flags & ~MAIL_DELETED)) {
		mail_log_action(_mail->transaction, _mail,
				MAIL_LOG_EVENT_FLAG_CHANGE, NULL);
	}
}

static void
mail_log_mail_update_keywords(struct mail *_mail, enum modify_type modify_type,
			      struct mail_keywords *keywords)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *lmail = MAIL_LOG_MAIL_CONTEXT(mail);
	const char *const *old_keywords, *const *new_keywords;
	unsigned int i;

	old_keywords = mail_get_keywords(_mail);
	lmail->super.update_keywords(_mail, modify_type, keywords);
	new_keywords = mail_get_keywords(_mail);

	for (i = 0; old_keywords[i] != NULL && new_keywords[i] != NULL; i++) {
		if (strcmp(old_keywords[i], new_keywords[i]) != 0)
			break;
	}

	if (old_keywords[i] != NULL || new_keywords[i] != NULL) {
		mail_log_action(_mail->transaction, _mail,
				MAIL_LOG_EVENT_FLAG_CHANGE, NULL);
	}
}

static struct mail *
mail_log_mail_alloc(struct mailbox_transaction_context *t,
		    enum mail_fetch_field wanted_fields,
		    struct mailbox_header_lookup_ctx *wanted_headers)
{
	union mailbox_module_context *lbox = MAIL_LOG_CONTEXT(t->box);
	union mail_module_context *lmail;
	struct mail *_mail;
	struct mail_private *mail;

	_mail = lbox->super.mail_alloc(t, wanted_fields, wanted_headers);
	mail = (struct mail_private *)_mail;

	lmail = p_new(mail->pool, union mail_module_context, 1);
	lmail->super = mail->v;

	mail->v.update_flags = mail_log_mail_update_flags;
	mail->v.update_keywords = mail_log_mail_update_keywords;
	mail->v.expunge = mail_log_mail_expunge;
	MODULE_CONTEXT_SET_SELF(mail, mail_log_mail_module, lmail);
	return _mail;
}

static int
mail_log_copy(struct mail_save_context *ctx, struct mail *mail)
{
	union mailbox_module_context *lbox =
		MAIL_LOG_CONTEXT(ctx->transaction->box);
	const char *name;

	if (lbox->super.copy(ctx, mail) < 0)
		return -1;

	T_BEGIN {
		name = str_sanitize(mailbox_get_vname(ctx->transaction->box),
				    MAILBOX_NAME_LOG_LEN);
		mail_log_action(ctx->transaction, mail,
				MAIL_LOG_EVENT_COPY, name);
	} T_END;
	return 0;
}

static int
mail_log_save_begin(struct mail_save_context *ctx, struct istream *input)
{
	struct mail_log_transaction_context *lt =
		MAIL_LOG_CONTEXT(ctx->transaction);
	union mailbox_module_context *lbox =
		MAIL_LOG_CONTEXT(ctx->transaction->box);

	if (ctx->dest_mail == NULL) {
		if (lt->tmp_mail == NULL)
			lt->tmp_mail = mail_alloc(ctx->transaction, 0, NULL);
		ctx->dest_mail = lt->tmp_mail;
	}

	return lbox->super.save_begin(ctx, input);
}

static int mail_log_save_finish(struct mail_save_context *ctx)
{
	union mailbox_module_context *lbox =
		MAIL_LOG_CONTEXT(ctx->transaction->box);

	if (lbox->super.save_finish(ctx) < 0)
		return -1;

	T_BEGIN {
		mail_log_action(ctx->transaction, ctx->dest_mail,
				MAIL_LOG_EVENT_APPEND, NULL);
	} T_END;
	return 0;
}

static struct mailbox_transaction_context *
mail_log_transaction_begin(struct mailbox *box,
			   enum mailbox_transaction_flags flags)
{
	union mailbox_module_context *lbox = MAIL_LOG_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct mail_log_transaction_context *lt;
	pool_t pool;

	t = lbox->super.transaction_begin(box, flags);

	pool = pool_alloconly_create("mail log transaction", 1024);
	lt = p_new(pool, struct mail_log_transaction_context, 1);
	lt->pool = pool;
	MODULE_CONTEXT_SET(t, mail_log_storage_module, lt);
	return t;
}

static int
mail_log_transaction_commit(struct mailbox_transaction_context *t,
			    uint32_t *uid_validity_r,
			    uint32_t *first_saved_uid_r,
			    uint32_t *last_saved_uid_r)
{
	struct mail_log_transaction_context *lt = MAIL_LOG_CONTEXT(t);
	union mailbox_module_context *lbox = MAIL_LOG_CONTEXT(t->box);
	struct mail_log_user *muser =
		MAIL_LOG_USER_CONTEXT(t->box->storage->user);

	if (lt->changes > 0 && muser->group_events)
		mail_log_group_changes(t->box, lt);
	if (lt->tmp_mail != NULL)
		mail_free(&lt->tmp_mail);
	pool_unref(&lt->pool);

	return lbox->super.transaction_commit(t, uid_validity_r,
					      first_saved_uid_r,
					      last_saved_uid_r);
}

static void
mail_log_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct mail_log_transaction_context *lt = MAIL_LOG_CONTEXT(t);
	union mailbox_module_context *lbox = MAIL_LOG_CONTEXT(t->box);
	struct mail_log_user *muser =
		MAIL_LOG_USER_CONTEXT(t->box->storage->user);

	if (lt->changes > 0 && !muser->group_events) {
		i_info("Transaction rolled back: "
		       "Ignore last %u changes", lt->changes);
	}
	if (lt->tmp_mail != NULL)
		mail_free(&lt->tmp_mail);
	pool_unref(&lt->pool);

	lbox->super.transaction_rollback(t);
}

static struct mailbox *
mail_log_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		       const char *name, struct istream *input,
		       enum mailbox_flags flags)
{
	union mail_storage_module_context *lstorage = MAIL_LOG_CONTEXT(storage);
	struct mailbox *box;
	union mailbox_module_context *lbox;

	box = lstorage->super.mailbox_alloc(storage, list, name, input, flags);

	lbox = p_new(box->pool, union mailbox_module_context, 1);
	lbox->super = box->v;

	box->v.mail_alloc = mail_log_mail_alloc;
	box->v.copy = mail_log_copy;
	box->v.save_begin = mail_log_save_begin;
	box->v.save_finish = mail_log_save_finish;
	box->v.transaction_begin = mail_log_transaction_begin;
	box->v.transaction_commit = mail_log_transaction_commit;
	box->v.transaction_rollback = mail_log_transaction_rollback;
	MODULE_CONTEXT_SET_SELF(box, mail_log_storage_module, lbox);
	return box;
}

static int
mail_log_mailbox_list_delete(struct mailbox_list *list, const char *name)
{
	union mailbox_list_module_context *llist = MAIL_LOG_LIST_CONTEXT(list);
	struct mail_log_user *muser = MAIL_LOG_USER_CONTEXT(list->ns->user);

	if (llist->super.delete_mailbox(list, name) < 0)
		return -1;

	if ((muser->events & MAIL_LOG_EVENT_MAILBOX_DELETE) == 0)
		return 0;

	i_info("Mailbox deleted: %s", str_sanitize(name, MAILBOX_NAME_LOG_LEN));
	return 0;
}

static int
mail_log_mailbox_list_rename(struct mailbox_list *oldlist, const char *oldname,
			     struct mailbox_list *newlist, const char *newname,
			     bool rename_children)
{
	union mailbox_list_module_context *llist =
		MAIL_LOG_LIST_CONTEXT(oldlist);
	struct mail_log_user *muser = MAIL_LOG_USER_CONTEXT(oldlist->ns->user);

	if (llist->super.rename_mailbox(oldlist, oldname, newlist, newname,
					rename_children) < 0)
		return -1;

	if ((muser->events & MAIL_LOG_EVENT_MAILBOX_RENAME) == 0)
		return 0;

	i_info("Mailbox renamed: %s -> %s",
	       str_sanitize(oldname, MAILBOX_NAME_LOG_LEN),
	       str_sanitize(newname, MAILBOX_NAME_LOG_LEN));
	return 0;
}

static void mail_log_mail_storage_created(struct mail_storage *storage)
{
	union mail_storage_module_context *lstorage;

	lstorage = p_new(storage->pool, union mail_storage_module_context, 1);
	lstorage->super = storage->v;
	storage->v.mailbox_alloc = mail_log_mailbox_alloc;

	MODULE_CONTEXT_SET_SELF(storage, mail_log_storage_module, lstorage);

	if (mail_log_next_hook_mail_storage_created != NULL)
		mail_log_next_hook_mail_storage_created(storage);
}

static void mail_log_mailbox_list_created(struct mailbox_list *list)
{
	union mailbox_list_module_context *llist;

	llist = p_new(list->pool, union mailbox_list_module_context, 1);
	llist->super = list->v;
	list->v.delete_mailbox = mail_log_mailbox_list_delete;
	list->v.rename_mailbox = mail_log_mailbox_list_rename;

	MODULE_CONTEXT_SET_SELF(list, mail_log_mailbox_list_module, llist);

	if (mail_log_next_hook_mailbox_list_created != NULL)
		mail_log_next_hook_mailbox_list_created(list);
}

static int mail_log_parse_fields(const char *str, enum mail_log_field *fields_r)
{
	const char *const *tmp;
	static enum mail_log_field field, fields = 0;

	for (tmp = t_strsplit_spaces(str, ", "); *tmp != NULL; tmp++) {
		field = mail_log_field_find(*tmp);
		if (field == 0) {
			i_error("Unknown field in mail_log_fields: '%s'", *tmp);
			return -1;
		}
		fields |= field;
	}
	*fields_r = fields;
	return 0;
}

static int mail_log_parse_events(const char *str, enum mail_log_event *events_r)
{
	const char *const *tmp;
	static enum mail_log_event event, events = 0;

	for (tmp = t_strsplit_spaces(str, ", "); *tmp != NULL; tmp++) {
		event = mail_log_event_find(*tmp);
		if (event == 0) {
			i_error("Unknown event in mail_log_events: '%s'", *tmp);
			return -1;
		}
		events |= event;
	}
	*events_r = events;
	return 0;
}

static void
mail_log_read_settings(struct mail_user *user, struct mail_log_user *muser)
{
	const char *str;

	str = mail_user_plugin_getenv(user, "mail_log_fields");
	if (str == NULL || mail_log_parse_fields(str, &muser->fields) < 0)
		muser->fields = MAIL_LOG_DEFAULT_FIELDS;

	str = mail_user_plugin_getenv(user, "mail_log_events");
	if (str == NULL || mail_log_parse_events(str, &muser->events) < 0)
		muser->events = MAIL_LOG_DEFAULT_EVENTS;

	muser->group_events =
		mail_user_plugin_getenv(user, "mail_log_group_events") != NULL;
}

static void mail_log_mail_user_created(struct mail_user *user)
{
	struct mail_log_user *muser;

	muser = p_new(user->pool, struct mail_log_user, 1);
	mail_log_read_settings(user, muser);
	MODULE_CONTEXT_SET(user, mail_log_mail_user_module, muser);

	if (mail_log_next_hook_mail_user_created != NULL)
		mail_log_next_hook_mail_user_created(user);
}

void mail_log_plugin_init(void)
{
	mail_log_next_hook_mail_storage_created = hook_mail_storage_created;
	hook_mail_storage_created = mail_log_mail_storage_created;

	mail_log_next_hook_mailbox_list_created = hook_mailbox_list_created;
	hook_mailbox_list_created = mail_log_mailbox_list_created;

	mail_log_next_hook_mail_user_created = hook_mail_user_created;
	hook_mail_user_created = mail_log_mail_user_created;
}

void mail_log_plugin_deinit(void)
{
	hook_mail_storage_created = mail_log_next_hook_mail_storage_created;
	hook_mailbox_list_created = mail_log_next_hook_mailbox_list_created;
	hook_mail_user_created = mail_log_next_hook_mail_user_created;
}
