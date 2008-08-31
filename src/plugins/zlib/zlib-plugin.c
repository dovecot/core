/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream-zlib.h"
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

#ifndef HAVE_ZLIB
#  define i_stream_create_zlib NULL
#endif
#ifndef HAVE_BZLIB
#  define i_stream_create_bzlib NULL
#endif

struct zlib_handler {
	const char *ext;
	bool (*is_compressed)(struct istream *input);
	struct istream *(*create_istream)(int fd);
};

const char *zlib_plugin_version = PACKAGE_VERSION;

static void (*zlib_next_hook_mail_storage_created)
	(struct mail_storage *storage);

static MODULE_CONTEXT_DEFINE_INIT(zlib_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(zlib_mail_module, &mail_module_register);

static bool is_compressed_zlib(struct istream *input)
{
	const unsigned char *data;
	size_t size;

	/* Peek in to the stream and see if it looks like it's compressed
	   (based on its header). This also means that users can try to exploit
	   security holes in the uncompression library by APPENDing a specially
	   crafted mail. So let's hope zlib is free of holes. */
	if (i_stream_read_data(input, &data, &size, 1) <= 0)
		return FALSE;
	i_assert(size >= 2);

	return data[0] == 31 && data[1] == 139;
}

static bool is_compressed_bzlib(struct istream *input)
{
	const unsigned char *data;
	size_t size;

	if (i_stream_read_data(input, &data, &size, 4+6 - 1) <= 0)
		return FALSE;
	if (data[0] != 'B' || data[1] != 'Z')
		return FALSE;
	if (data[2] != 'h' && data[2] != '0')
		return FALSE;
	if (data[3] < '1' || data[3] > '9')
		return FALSE;
	return memcmp(data + 4, "\x31\x41\x59\x26\x53\x59", 6) == 0;
}

static struct zlib_handler zlib_handlers[] = {
	{ ".gz", is_compressed_zlib, i_stream_create_zlib },
	{ ".bz2", is_compressed_bzlib, i_stream_create_bzlib }
};

static struct zlib_handler *zlib_get_zlib_handler(struct istream *input)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(zlib_handlers); i++) {
		if (zlib_handlers[i].is_compressed(input))
			return &zlib_handlers[i];
	}
	return NULL;
}

static struct zlib_handler *zlib_get_zlib_handler_ext(const char *name)
{
	unsigned int i, len, name_len = strlen(name);

	for (i = 0; i < N_ELEMENTS(zlib_handlers); i++) {
		len = strlen(zlib_handlers[i].ext);
		if (name_len > len &&
		    strcmp(name + name_len - len, zlib_handlers[i].ext) == 0)
			return &zlib_handlers[i];
	}
	return NULL;
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
	struct zlib_handler *handler;
	int fd;

	if (imail->data.stream != NULL) {
		return zmail->super.get_stream(_mail, hdr_size, body_size,
					       stream_r);
	}

	if (zmail->super.get_stream(_mail, NULL, NULL, &input) < 0)
		return -1;
	i_assert(input == imail->data.stream);

	handler = zlib_get_zlib_handler(imail->data.stream);
	if (handler != NULL) {
		if (handler->create_istream == NULL) {
			mail_storage_set_critical(_mail->box->storage,
				"zlib plugin: Detected %s compression "
				"but support not compiled in", handler->ext);
			fd = -1;
		} else {
			fd = dup(i_stream_get_fd(imail->data.stream));
			if (fd == -1) {
				mail_storage_set_critical(_mail->box->storage,
					"zlib plugin: dup() failed: %m");
			}
		}

		imail->data.destroying_stream = TRUE;
		i_stream_unref(&imail->data.stream);
		i_assert(!imail->data.destroying_stream);

		if (fd == -1)
			return -1;
		imail->data.stream = handler->create_istream(fd);
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

static struct istream *
zlib_mailbox_open_input(struct mail_storage *storage, const char *name)
{
	struct zlib_handler *handler;
	const char *path;
	int fd;
	bool is_file;

	handler = zlib_get_zlib_handler_ext(name);
	if (handler == NULL || handler->create_istream == NULL)
		return NULL;

	path = mail_storage_get_mailbox_path(storage, name, &is_file);
	if (is_file && path != NULL) {
		/* looks like a compressed single file mailbox. we should be
		   able to handle this. */
		fd = open(path, O_RDONLY);
		if (fd != -1)
			return handler->create_istream(fd);
	}
	return NULL;
}

static struct mailbox *
zlib_mailbox_open(struct mail_storage *storage, const char *name,
		  struct istream *input, enum mailbox_open_flags flags)
{
	union mail_storage_module_context *qstorage = ZLIB_CONTEXT(storage);
	struct mailbox *box;
	struct istream *zlib_input = NULL;

	if (input == NULL && strcmp(storage->name, "mbox") == 0)
		input = zlib_input = zlib_mailbox_open_input(storage, name);

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
