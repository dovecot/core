/* Copyright (c) 2005-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "istream-seekable.h"
#include "ostream.h"
#include "str.h"
#include "mail-user.h"
#include "index-storage.h"
#include "index-mail.h"
#include "compression.h"
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

#define MAX_INBUF_SIZE (1024*1024)
#define ZLIB_MAIL_CACHE_EXPIRE_MSECS (60*1000)

struct zlib_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct mail *tmp_mail;
};

struct zlib_mail_cache {
	struct timeout *to;
	struct mailbox *box;
	uint32_t uid;

	struct istream *input;
};

struct zlib_user {
	union mail_user_module_context module_ctx;

	struct zlib_mail_cache cache;

	const struct compression_handler *save_handler;
	unsigned int save_level;
};

const char *zlib_plugin_version = DOVECOT_ABI_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(zlib_user_module,
				  &mail_user_module_register);
static MODULE_CONTEXT_DEFINE_INIT(zlib_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(zlib_mail_module, &mail_module_register);

static void zlib_mail_cache_close(struct zlib_user *zuser)
{
	struct zlib_mail_cache *cache = &zuser->cache;

	if (cache->to != NULL)
		timeout_remove(&cache->to);
	if (cache->input != NULL)
		i_stream_unref(&cache->input);
	memset(cache, 0, sizeof(*cache));
}

static struct istream *
zlib_mail_cache_open(struct zlib_user *zuser, struct mail *mail,
		     struct istream *input)
{
	struct zlib_mail_cache *cache = &zuser->cache;
	struct istream *inputs[2];
	string_t *temp_prefix = t_str_new(128);

	zlib_mail_cache_close(zuser);

	/* zlib istream is seekable, but very slow. create a seekable istream
	   which we can use to quickly seek around in the stream that's been
	   read so far. usually the partial IMAP FETCHes continue from where
	   the previous left off, so this isn't strictly necessary, but with
	   the way lib-imap-storage's CRLF-cache works it has to seek backwards
	   somewhat, which causes a zlib stream reset. And the CRLF-cache isn't
	   easy to fix.. */
	input->seekable = FALSE;
	inputs[0] = input;
	inputs[1] = NULL;
	mail_user_set_get_temp_prefix(temp_prefix, mail->box->storage->user->set);
	input = i_stream_create_seekable_path(inputs,
				i_stream_get_max_buffer_size(inputs[0]),
				str_c(temp_prefix));
	i_stream_unref(&inputs[0]);

	cache->to = timeout_add(ZLIB_MAIL_CACHE_EXPIRE_MSECS,
				zlib_mail_cache_close, zuser);
	cache->box = mail->box;
	cache->uid = mail->uid;
	cache->input = input;

	/* index-mail wants the stream to be destroyed at close, so create
	   a new stream instead of just increasing reference. */
	return i_stream_create_limit(cache->input, (uoff_t)-1);
}

static int zlib_istream_opened(struct mail *_mail, struct istream **stream)
{
	struct zlib_user *zuser = ZLIB_USER_CONTEXT(_mail->box->storage->user);
	struct zlib_mail_cache *cache = &zuser->cache;
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *zmail = ZLIB_MAIL_CONTEXT(mail);
	struct istream *input;
	const struct compression_handler *handler;

	/* don't uncompress input when we are reading a mail that we're just
	   in the middle of saving, and we didn't do the compression ourself.
	   in such situation we're probably checking if the user-given input
	   looks compressed */
	if (_mail->saving && zuser->save_handler == NULL)
		return zmail->super.istream_opened(_mail, stream);

	if (cache->uid == _mail->uid && cache->box == _mail->box) {
		/* use the cached stream. when doing partial reads it should
		   already be seeked into the wanted offset. */
		i_stream_unref(stream);
		i_stream_seek(cache->input, 0);
		*stream = i_stream_create_limit(cache->input, (uoff_t)-1);
		return zmail->super.istream_opened(_mail, stream);
	}

	handler = compression_detect_handler(*stream);
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

		*stream = zlib_mail_cache_open(zuser, _mail, *stream);
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

	if (compression_detect_handler(input) != NULL) {
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

	output = zuser->save_handler->create_ostream(ctx->data.output,
						     zuser->save_level);
	o_stream_unref(&ctx->data.output);
	ctx->data.output = output;
	o_stream_cork(ctx->data.output);
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
	const struct compression_handler *handler;
	struct istream *input;
	struct stat st;
	int fd;

	handler = compression_lookup_handler_from_ext(box->name);
	if (handler == NULL || handler->create_istream == NULL)
		return 0;

	if (mail_storage_is_mailbox_file(box->storage)) {
		/* looks like a compressed single file mailbox. we should be
		   able to handle this. */
		const char *box_path = mailbox_get_path(box);

		fd = open(box_path, O_RDONLY);
		if (fd == -1) {
			/* let the standard handler figure out what to do
			   with the failure */
			return 0;
		}
		if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
			i_close_fd(&fd);
			return 0;
		}
		input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
		i_stream_set_name(input, box_path);
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

static void zlib_mailbox_close(struct mailbox *box)
{
	union mailbox_module_context *zbox = ZLIB_CONTEXT(box);
	struct zlib_user *zuser = ZLIB_USER_CONTEXT(box->storage->user);

	if (zuser->cache.box == box)
		zlib_mail_cache_close(zuser);
	zbox->super.close(box);
}

static void zlib_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	union mailbox_module_context *zbox;
	enum mail_storage_class_flags class_flags = box->storage->class_flags;

	zbox = p_new(box->pool, union mailbox_module_context, 1);
	zbox->super = *v;
	box->vlast = &zbox->super;
	v->open = zlib_mailbox_open;
	v->close = zlib_mailbox_close;

	MODULE_CONTEXT_SET_SELF(box, zlib_storage_module, zbox);

	if ((class_flags & MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS) == 0 &&
	    (class_flags & MAIL_STORAGE_CLASS_FLAG_BINARY_DATA) != 0)
		zlib_permail_alloc_init(box, v);
}

static void zlib_mail_user_deinit(struct mail_user *user)
{
	struct zlib_user *zuser = ZLIB_USER_CONTEXT(user);

	zlib_mail_cache_close(zuser);
	zuser->module_ctx.super.deinit(user);
}

static void zlib_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct zlib_user *zuser;
	const char *name;

	zuser = p_new(user->pool, struct zlib_user, 1);
	zuser->module_ctx.super = *v;
	user->vlast = &zuser->module_ctx.super;
	v->deinit = zlib_mail_user_deinit;

	name = mail_user_plugin_getenv(user, "zlib_save");
	if (name != NULL && *name != '\0') {
		zuser->save_handler = compression_lookup_handler(name);
		if (zuser->save_handler == NULL)
			i_error("zlib_save: Unknown handler: %s", name);
		else if (zuser->save_handler->create_ostream == NULL) {
			i_error("zlib_save: Support not compiled in for handler: %s", name);
			zuser->save_handler = NULL;
		}
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
