/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "proxy-mail-storage.h"

static void _free(struct mail_storage *storage)
{
	struct proxy_mail_storage *s = (struct proxy_mail_storage *) storage;

	s->storage->free(s->storage);
}

static void _set_callbacks(struct mail_storage *storage,
			   struct mail_storage_callbacks *callbacks,
			   void *context)
{
	struct proxy_mail_storage *s = (struct proxy_mail_storage *) storage;

	s->storage->set_callbacks(s->storage, callbacks, context);
}

static struct mailbox *_open_mailbox(struct mail_storage *storage,
				     const char *name,
				     enum mailbox_open_flags flags)
{
	struct proxy_mail_storage *s = (struct proxy_mail_storage *) storage;

        return s->storage->open_mailbox(s->storage, name, flags);
}

static int _create_mailbox(struct mail_storage *storage, const char *name,
			   int only_hierarchy)
{
	struct proxy_mail_storage *s = (struct proxy_mail_storage *) storage;

	return s->storage->create_mailbox(s->storage, name, only_hierarchy);
}

static int _delete_mailbox(struct mail_storage *storage, const char *name)
{
	struct proxy_mail_storage *s = (struct proxy_mail_storage *) storage;

	return s->storage->delete_mailbox(s->storage, name);
}

static int _rename_mailbox(struct mail_storage *storage, const char *oldname,
			   const char *newname)
{
	struct proxy_mail_storage *s = (struct proxy_mail_storage *) storage;

	return s->storage->rename_mailbox(s->storage, oldname, newname);
}

static struct mailbox_list_context *
_list_mailbox_init(struct mail_storage *storage, const char *mask,
		   enum mailbox_list_flags flags)
{
	struct proxy_mail_storage *s = (struct proxy_mail_storage *) storage;

	return s->storage->list_mailbox_init(s->storage, mask, flags);
}

static int _set_subscribed(struct mail_storage *storage,
			   const char *name, int set)
{
	struct proxy_mail_storage *s = (struct proxy_mail_storage *) storage;

	return s->storage->set_subscribed(s->storage, name, set);
}

static int _get_mailbox_name_status(struct mail_storage *storage,
				    const char *name,
				    enum mailbox_name_status *status)
{
	struct proxy_mail_storage *s = (struct proxy_mail_storage *) storage;

	return s->storage->get_mailbox_name_status(s->storage, name, status);
}

static const char *_get_last_error(struct mail_storage *storage,
				   int *syntax_error)
{
	struct proxy_mail_storage *s = (struct proxy_mail_storage *) storage;

	return s->storage->get_last_error(s->storage, syntax_error);
}

void proxy_mail_storage_init(struct proxy_mail_storage *proxy,
			     struct mail_storage *storage)
{
	struct mail_storage *ps = &proxy->proxy_storage;

	proxy->storage = storage;

	ps->name = storage->name;
	ps->hierarchy_sep = storage->hierarchy_sep;

	ps->create = storage->create;
	ps->autodetect = storage->autodetect;
	ps->list_mailbox_deinit = storage->list_mailbox_deinit;
	ps->list_mailbox_next = storage->list_mailbox_next;

	ps->free = _free;
	ps->set_callbacks = _set_callbacks;
	ps->open_mailbox = _open_mailbox;
	ps->create_mailbox = _create_mailbox;
	ps->delete_mailbox = _delete_mailbox;
	ps->rename_mailbox = _rename_mailbox;
	ps->list_mailbox_init = _list_mailbox_init;
	ps->set_subscribed = _set_subscribed;
	ps->get_mailbox_name_status = _get_mailbox_name_status;
	ps->get_last_error = _get_last_error;
}
