/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "mail-user.h"
#include "dbox-single/sdbox-storage.h"
#include "dbox-multi/mdbox-storage.h"
#include "maildir/maildir-storage.h"
#include "index-storage.h"
#include "index-mail.h"
#include "istream-zlib.h"
#include "ostream-zlib.h"
#include "zlib-plugin.h"

#include <stdlib.h>
#include <fcntl.h>

#define ZLIB_PLUGIN_DEFAULT_LEVEL 6

#define ZLIB_CONTEXT(obj) \
	MODULE_CONTEXT(obj, zlib_storage_module)
#define ZLIB_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, zlib_mail_module)
#define ZLIB_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, zlib_user_module)

#ifndef HAVE_ZLIB
#  define i_stream_create_gz NULL
#  define o_stream_create_gz NULL
#endif
#ifndef HAVE_BZLIB
#  define i_stream_create_bz2 NULL
#  define o_stream_create_bz2 NULL
#endif

#define MAX_INBUF_SIZE (1024*1024)

struct zlib_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct mail *tmp_mail;
};

struct zlib_user {
	union mail_user_module_context module_ctx;

	const struct zlib_handler *save_handler;
	unsigned int save_level;
};

const char *zlib_plugin_version = DOVECOT_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(zlib_user_module,
				  &mail_user_module_register);
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

const struct zlib_handler *zlib_find_zlib_handler(const char *name)
{
	unsigned int i;

	for (i = 0; zlib_handlers[i].name != NULL; i++) {
		if (strcmp(name, zlib_handlers[i].name) == 0)
			return &zlib_handlers[i];
	}
	return NULL;
}

static const struct zlib_handler *zlib_get_zlib_handler(struct istream *input)
{
	unsigned int i;

	for (i = 0; zlib_handlers[i].name != NULL; i++) {
		if (zlib_handlers[i].is_compressed != NULL &&
		    zlib_handlers[i].is_compressed(input))
			return &zlib_handlers[i];
	}
	return NULL;
}

static const struct zlib_handler *zlib_get_zlib_handler_ext(const char *name)
{
	unsigned int i, len, name_len = strlen(name);

	for (i = 0; zlib_handlers[i].name != NULL; i++) {
		if (zlib_handlers[i].ext == NULL)
			continue;

		len = strlen(zlib_handlers[i].ext);
		if (name_len > len &&
		    strcmp(name + name_len - len, zlib_handlers[i].ext) == 0)
			return &zlib_handlers[i];
	}
	return NULL;
}

static int zlib_istream_opened(struct mail *_mail, struct istream **stream)
{
	struct zlib_user *zuser = ZLIB_USER_CONTEXT(_mail->box->storage->user);
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *zmail = ZLIB_MAIL_CONTEXT(mail);
	struct istream *input;
	const struct zlib_handler *handler;

	/* don't uncompress input when we are reading a mail that we're just
	   in the middle of saving, and we didn't do the compression ourself.
	   in such situation we're probably checking if the user-given input
	   looks compressed */
	if (_mail->saving && zuser->save_handler == NULL)
		return zmail->super.istream_opened(_mail, stream);

	handler = zlib_get_zlib_handler(*stream);
	if (handler != NULL) {
		if (handler->create_istream == NULL) {
			mail_storage_set_critical(_mail->box->storage,
				"zlib plugin: Detected %s compression "
				"but support not compiled in", handler->ext);
			return -1;
		}

		input = *stream;
		*stream = handler->create_istream(input, TRUE);
		i_stream_unref(&input);
	}
	return zmail->super.istream_opened(_mail, stream);
}

static void zlib_mail_allocated(struct mail *_mail)
{
	struct zlib_transaction_context *zt = ZLIB_CONTEXT(_mail->transaction);
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *zmail;

	if (zt == NULL)
		return;

	zmail = p_new(mail->pool, union mail_module_context, 1);
	zmail->super = *v;
	mail->vlast = &zmail->super;

	v->istream_opened = zlib_istream_opened;
	MODULE_CONTEXT_SET_SELF(mail, zlib_mail_module, zmail);
}

static struct mailbox_transaction_context *
zlib_mailbox_transaction_begin(struct mailbox *box,
			       enum mailbox_transaction_flags flags)
{
	union mailbox_module_context *zbox = ZLIB_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct zlib_transaction_context *zt;

	t = zbox->super.transaction_begin(box, flags);

	zt = i_new(struct zlib_transaction_context, 1);

	MODULE_CONTEXT_SET(t, zlib_storage_module, zt);
	return t;
}

static void
zlib_mailbox_transaction_rollback(struct mailbox_transaction_context *t)
{
	union mailbox_module_context *zbox = ZLIB_CONTEXT(t->box);
	struct zlib_transaction_context *zt = ZLIB_CONTEXT(t);

	if (zt->tmp_mail != NULL)
		mail_free(&zt->tmp_mail);

	zbox->super.transaction_rollback(t);
	i_free(zt);
}

static int
zlib_mailbox_transaction_commit(struct mailbox_transaction_context *t,
				struct mail_transaction_commit_changes *changes_r)
{
	union mailbox_module_context *zbox = ZLIB_CONTEXT(t->box);
	struct zlib_transaction_context *zt = ZLIB_CONTEXT(t);
	int ret;

	if (zt->tmp_mail != NULL)
		mail_free(&zt->tmp_mail);

	ret = zbox->super.transaction_commit(t, changes_r);
	i_free(zt);
	return ret;
}

static int
zlib_mail_save_begin(struct mail_save_context *ctx, struct istream *input)
{
	struct mailbox_transaction_context *t = ctx->transaction;
	struct zlib_transaction_context *zt = ZLIB_CONTEXT(t);
	union mailbox_module_context *zbox = ZLIB_CONTEXT(t->box);

	if (ctx->dest_mail == NULL) {
		if (zt->tmp_mail == NULL) {
			zt->tmp_mail = mail_alloc(t, MAIL_FETCH_PHYSICAL_SIZE,
						  NULL);
		}
		ctx->dest_mail = zt->tmp_mail;
	}

	return zbox->super.save_begin(ctx, input);
}

static int zlib_mail_save_finish(struct mail_save_context *ctx)
{
	struct mailbox *box = ctx->transaction->box;
	union mailbox_module_context *zbox = ZLIB_CONTEXT(box);
	struct istream *input;

	if (zbox->super.save_finish(ctx) < 0)
		return -1;

	if (mail_get_stream(ctx->dest_mail, NULL, NULL, &input) < 0)
		return -1;

	if (zlib_get_zlib_handler(input) != NULL) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			"Saving mails compressed by client isn't supported");
		return -1;
	}
	return 0;
}

static int
zlib_mail_save_compress_begin(struct mail_save_context *ctx,
			      struct istream *input)
{
	struct mailbox *box = ctx->transaction->box;
	struct zlib_user *zuser = ZLIB_USER_CONTEXT(box->storage->user);
	union mailbox_module_context *zbox = ZLIB_CONTEXT(box);
	struct ostream *output;

	if (zbox->super.save_begin(ctx, input) < 0)
		return -1;

	output = zuser->save_handler->create_ostream(ctx->output,
						     zuser->save_level);
	o_stream_unref(&ctx->output);
	ctx->output = output;
	o_stream_cork(ctx->output);
	return 0;
}

static void
zlib_permail_alloc_init(struct mailbox *box, struct mailbox_vfuncs *v)
{
	struct zlib_user *zuser = ZLIB_USER_CONTEXT(box->storage->user);

	v->transaction_begin = zlib_mailbox_transaction_begin;
	v->transaction_rollback = zlib_mailbox_transaction_rollback;
	v->transaction_commit = zlib_mailbox_transaction_commit;
	if (zuser->save_handler == NULL) {
		v->save_begin = zlib_mail_save_begin;
		v->save_finish = zlib_mail_save_finish;
	} else {
		v->save_begin = zlib_mail_save_compress_begin;
	}
}

static int zlib_mailbox_open_input(struct mailbox *box)
{
	const struct zlib_handler *handler;
	struct istream *input;
	int fd;

	handler = zlib_get_zlib_handler_ext(box->name);
	if (handler == NULL || handler->create_istream == NULL)
		return 0;

	if (mail_storage_is_mailbox_file(box->storage)) {
		/* looks like a compressed single file mailbox. we should be
		   able to handle this. */
		fd = open(box->path, O_RDONLY);
		if (fd == -1) {
			mail_storage_set_critical(box->storage,
				"open(%s) failed: %m", box->path);
			return -1;
		}
		input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
		i_stream_set_name(input, box->path);
		box->input = handler->create_istream(input, TRUE);
		i_stream_unref(&input);
		box->flags |= MAILBOX_FLAG_READONLY;
	}
	return 0;
}

static int zlib_mailbox_open(struct mailbox *box)
{
	union mailbox_module_context *zbox = ZLIB_CONTEXT(box);

	if (box->input == NULL &&
	    (box->storage->class_flags &
	     MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS) != 0) {
		if (zlib_mailbox_open_input(box) < 0)
			return -1;
	}

	return zbox->super.open(box);
}

static void zlib_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	union mailbox_module_context *zbox;

	zbox = p_new(box->pool, union mailbox_module_context, 1);
	zbox->super = *v;
	box->vlast = &zbox->super;
	v->open = zlib_mailbox_open;

	MODULE_CONTEXT_SET_SELF(box, zlib_storage_module, zbox);

	if (strcmp(box->storage->name, MAILDIR_STORAGE_NAME) == 0 ||
	    strcmp(box->storage->name, MDBOX_STORAGE_NAME) == 0 ||
	    strcmp(box->storage->name, SDBOX_STORAGE_NAME) == 0)
		zlib_permail_alloc_init(box, v);
}

static void zlib_mail_user_created(struct mail_user *user)
{
	struct zlib_user *zuser;
	const char *name;

	zuser = p_new(user->pool, struct zlib_user, 1);

	name = mail_user_plugin_getenv(user, "zlib_save");
	if (name != NULL && *name != '\0') {
		zuser->save_handler = zlib_find_zlib_handler(name);
		if (zuser->save_handler == NULL)
			i_error("zlib_save: Unknown handler: %s", name);
	}
	name = mail_user_plugin_getenv(user, "zlib_save_level");
	if (name != NULL) {
		if (str_to_uint(name, &zuser->save_level) < 0 ||
		    zuser->save_level < 1 || zuser->save_level > 9) {
			i_error("zlib_save_level: Level must be between 1..9");
			zuser->save_level = 0;
		}
	}
	if (zuser->save_level == 0)
		zuser->save_level = ZLIB_PLUGIN_DEFAULT_LEVEL;
	MODULE_CONTEXT_SET(user, zlib_user_module, zuser);
}

static struct mail_storage_hooks zlib_mail_storage_hooks = {
	.mail_user_created = zlib_mail_user_created,
	.mailbox_allocated = zlib_mailbox_allocated,
	.mail_allocated = zlib_mail_allocated
};

void zlib_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &zlib_mail_storage_hooks);
}

void zlib_plugin_deinit(void)
{
	mail_storage_hooks_remove(&zlib_mail_storage_hooks);
}

const struct zlib_handler zlib_handlers[] = {
	{ "gz", ".gz", is_compressed_zlib,
	  i_stream_create_gz, o_stream_create_gz },
	{ "bz2", ".bz2", is_compressed_bzlib,
	  i_stream_create_bz2, o_stream_create_bz2 },
	{ "deflate", NULL, NULL,
	  i_stream_create_deflate, o_stream_create_deflate },
	{ NULL, NULL, NULL, NULL, NULL }
};
