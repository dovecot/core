/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "str-sanitize.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "mail-log-plugin.h"

#define MAILBOX_NAME_LOG_LEN 64
#define MSGID_LOG_LEN 80

#define MAIL_LOG_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_log_storage_module)
#define MAIL_LOG_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_log_mail_module)
#define MAIL_LOG_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_log_mailbox_list_module)

const char *mail_log_plugin_version = PACKAGE_VERSION;

static void (*mail_log_next_hook_mail_storage_created)
	(struct mail_storage *storage);
static void (*mail_log_next_hook_mailbox_list_created)
	(struct mailbox_list *list);

static MODULE_CONTEXT_DEFINE_INIT(mail_log_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(mail_log_mail_module, &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(mail_log_mailbox_list_module,
				  &mailbox_list_module_register);

static void mail_log_action(struct mail *mail, const char *action)
{
	const char *msgid, *mailbox_str;

	mailbox_str = mailbox_get_name(mail->box);
	if (strcmp(mailbox_str, "INBOX") == 0) {
		/* most operations are for INBOX, and POP3 has only INBOX,
		   so don't add it. */
		mailbox_str = "";
	} else {
		mailbox_str = str_sanitize(mailbox_str, 80);
		mailbox_str = t_strconcat(", box=", mailbox_str, NULL);
	}

	msgid = mail_get_first_header(mail, "Message-ID");
	i_info("%s: uid=%u, msgid=%s%s", action, mail->uid,
	       msgid == NULL ? "(null)" : str_sanitize(msgid, MSGID_LOG_LEN),
	       mailbox_str);
}

static int mail_log_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *lmail = MAIL_LOG_MAIL_CONTEXT(mail);

	if (lmail->super.expunge(_mail) < 0)
		return -1;

	mail_log_action(_mail, "expunged");
	return 0;
}

static int
mail_log_mail_update_flags(struct mail *_mail, enum modify_type modify_type,
			   enum mail_flags flags)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *lmail = MAIL_LOG_MAIL_CONTEXT(mail);
	enum mail_flags old_flags, new_flags;

	old_flags = mail_get_flags(_mail);
	if (lmail->super.update_flags(_mail, modify_type, flags) < 0)
		return -1;

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
	if (((old_flags ^ new_flags) & MAIL_DELETED) == 0)
		return 0;

	mail_log_action(_mail, (new_flags & MAIL_DELETED) != 0 ?
			"deleted" : "undeleted");
	return 0;
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
	mail->v.expunge = mail_log_mail_expunge;
	MODULE_CONTEXT_SET_SELF(mail, mail_log_mail_module, lmail);
	return _mail;
}

static int
mail_log_copy(struct mailbox_transaction_context *t, struct mail *mail,
	      enum mail_flags flags, struct mail_keywords *keywords,
	      struct mail *dest_mail)
{
	union mailbox_module_context *lbox = MAIL_LOG_CONTEXT(t->box);
	const char *name;

	if (lbox->super.copy(t, mail, flags, keywords, dest_mail) < 0)
		return -1;

	t_push();
	name = str_sanitize(mailbox_get_name(t->box), MAILBOX_NAME_LOG_LEN);
	mail_log_action(mail, t_strdup_printf("copy -> %s", name));
	t_pop();
	return 0;
}

static struct mailbox *
mail_log_mailbox_open(struct mail_storage *storage, const char *name,
		      struct istream *input, enum mailbox_open_flags flags)
{
	union mail_storage_module_context *lstorage = MAIL_LOG_CONTEXT(storage);
	struct mailbox *box;
	union mailbox_module_context *lbox;

	box = lstorage->super.mailbox_open(storage, name, input, flags);
	if (box == NULL)
		return NULL;

	lbox = p_new(box->pool, union mailbox_module_context, 1);
	lbox->super = box->v;

	box->v.mail_alloc = mail_log_mail_alloc;
	box->v.copy = mail_log_copy;
	MODULE_CONTEXT_SET_SELF(box, mail_log_storage_module, lbox);
	return box;
}

static int
mail_log_mailbox_list_delete(struct mailbox_list *list, const char *name)
{
	union mailbox_list_module_context *llist = MAIL_LOG_LIST_CONTEXT(list);

	if (llist->super.delete_mailbox(list, name) < 0)
		return -1;

	i_info("Mailbox deleted: %s", str_sanitize(name, MAILBOX_NAME_LOG_LEN));
	return 0;
}

static void mail_log_mail_storage_created(struct mail_storage *storage)
{
	union mail_storage_module_context *lstorage;

	if (mail_log_next_hook_mail_storage_created != NULL)
		mail_log_next_hook_mail_storage_created(storage);

	lstorage = p_new(storage->pool, union mail_storage_module_context, 1);
	lstorage->super = storage->v;
	storage->v.mailbox_open = mail_log_mailbox_open;

	MODULE_CONTEXT_SET_SELF(storage, mail_log_storage_module, lstorage);
}

static void mail_log_mailbox_list_created(struct mailbox_list *list)
{
	union mailbox_list_module_context *llist;

	if (mail_log_next_hook_mailbox_list_created != NULL)
		mail_log_next_hook_mailbox_list_created(list);

	llist = p_new(list->pool, union mailbox_list_module_context, 1);
	llist->super = list->v;
	list->v.delete_mailbox = mail_log_mailbox_list_delete;

	MODULE_CONTEXT_SET_SELF(list, mail_log_mailbox_list_module, llist);
}

void mail_log_plugin_init(void)
{
	mail_log_next_hook_mail_storage_created = hook_mail_storage_created;
	hook_mail_storage_created = mail_log_mail_storage_created;

	mail_log_next_hook_mailbox_list_created = hook_mailbox_list_created;
	hook_mailbox_list_created = mail_log_mailbox_list_created;
}

void mail_log_plugin_deinit(void)
{
	hook_mail_storage_created = mail_log_next_hook_mail_storage_created;
	hook_mailbox_list_created = mail_log_next_hook_mailbox_list_created;
}
