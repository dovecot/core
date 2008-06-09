/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream-zlib.h"
#include "home-expand.h"
#include "istream.h"
#include "maildir/maildir-storage.h"
#include "maildir/maildir-uidlist.h"
#include "index-mail.h"
#include "zlib-plugin.h"

#include <fcntl.h>

#define ZLIB_CONTEXT(obj) \
	MODULE_CONTEXT(obj, zlib_storage_module)
#define ZLIB_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, zlib_mail_module)

const char *zlib_plugin_version = PACKAGE_VERSION;

static void (*zlib_next_hook_mail_storage_created)
	(struct mail_storage *storage);

static MODULE_CONTEXT_DEFINE_INIT(zlib_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(zlib_mail_module, &mail_module_register);

static int zlib_mail_is_compressed(struct istream *mail)
{
	const unsigned char *zheader;
	size_t header_size;

	/* Peek in to the mail and see if it looks like it's compressed
	   (it has the correct 2 byte zlib header). This also means that users
	   can try to exploit security holes in zlib by APPENDing a specially
	   crafted mail. So let's hope zlib is free of holes. */
	if (i_stream_read_data(mail, &zheader, &header_size, 2) <= 0)
		return 0;
	i_stream_seek(mail, 0);

	return header_size >= 2 && zheader &&
		zheader[0] == 31 && zheader[1] == 139;
}

static int zlib_maildir_get_stream(struct mail *_mail,
				   struct message_size *hdr_size,
				   struct message_size *body_size,
				   struct istream **stream_r)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct index_mail *imail = (struct index_mail *)mail;
	union mail_module_context *zmail = ZLIB_MAIL_CONTEXT(mail);
	struct istream *input;
	int fd;

	if (imail->data.stream != NULL) {
		return zmail->super.get_stream(_mail, hdr_size, body_size,
					       stream_r);
	}

	if (zmail->super.get_stream(_mail, NULL, NULL, &input) < 0)
		return -1;
	i_assert(input == imail->data.stream);

	if (zlib_mail_is_compressed(imail->data.stream)) {
		fd = dup(i_stream_get_fd(imail->data.stream));
		if (fd == -1)
			i_error("zlib plugin: dup() failed: %m");

		imail->data.destroying_stream = TRUE;
		i_stream_unref(&imail->data.stream);
		i_assert(!imail->data.destroying_stream);

		if (fd == -1)
			return -1;
		imail->data.stream = i_stream_create_zlib(fd);
	}
	return index_mail_init_stream(imail, hdr_size, body_size, stream_r);
}

static struct mail *
zlib_maildir_mail_alloc(struct mailbox_transaction_context *t,
			enum mail_fetch_field wanted_fields,
			struct mailbox_header_lookup_ctx *wanted_headers)
{
	union mailbox_module_context *zbox = ZLIB_CONTEXT(t->box);
	union mail_module_context *zmail;
	struct mail *_mail;
	struct mail_private *mail;

	_mail = zbox->super.mail_alloc(t, wanted_fields, wanted_headers);
	mail = (struct mail_private *)_mail;

	zmail = p_new(mail->pool, union mail_module_context, 1);
	zmail->super = mail->v;

	mail->v.get_stream = zlib_maildir_get_stream;
	MODULE_CONTEXT_SET_SELF(mail, zlib_mail_module, zmail);
	return _mail;
}

static void zlib_maildir_open_init(struct mailbox *box)
{
	union mailbox_module_context *zbox;

	zbox = p_new(box->pool, union mailbox_module_context, 1);
	zbox->super = box->v;
	box->v.mail_alloc = zlib_maildir_mail_alloc;

	MODULE_CONTEXT_SET_SELF(box, zlib_storage_module, zbox);
}

static struct mailbox *
zlib_mailbox_open(struct mail_storage *storage, const char *name,
		  struct istream *input, enum mailbox_open_flags flags)
{
	union mail_storage_module_context *qstorage = ZLIB_CONTEXT(storage);
	struct mailbox *box;
	struct istream *zlib_input = NULL;
	size_t len = strlen(name);

	if (input == NULL && len > 3 && strcmp(name + len - 3, ".gz") == 0 &&
	    strcmp(storage->name, "mbox") == 0) {
		/* Looks like a .gz mbox file */
		const char *path;
		bool is_file;

		path = mail_storage_get_mailbox_path(storage, name, &is_file);
		if (is_file && path != NULL) {
			/* it's a single file mailbox. we can handle this. */
			int fd;

			fd = open(path, O_RDONLY);
			if (fd != -1)
				input = zlib_input = i_stream_create_zlib(fd);
		}
	}

	box = qstorage->super.mailbox_open(storage, name, input, flags);

	if (zlib_input != NULL)
		i_stream_unref(&zlib_input);

	if (box != NULL && strcmp(storage->name, "maildir") == 0)
		zlib_maildir_open_init(box);
	return box;
}

static void zlib_mail_storage_created(struct mail_storage *storage)
{
	union mail_storage_module_context *qstorage;

	qstorage = p_new(storage->pool, union mail_storage_module_context, 1);
	qstorage->super = storage->v;
	storage->v.mailbox_open = zlib_mailbox_open;

	MODULE_CONTEXT_SET_SELF(storage, zlib_storage_module, qstorage);

	if (zlib_next_hook_mail_storage_created != NULL)
		zlib_next_hook_mail_storage_created(storage);
}

void zlib_plugin_init(void)
{
	zlib_next_hook_mail_storage_created =
		hook_mail_storage_created;
	hook_mail_storage_created = zlib_mail_storage_created;
}

void zlib_plugin_deinit(void)
{
	hook_mail_storage_created =
		zlib_next_hook_mail_storage_created;
}
