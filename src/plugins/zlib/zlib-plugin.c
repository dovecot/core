/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

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

#include <fcntl.h>

#define ZLIB_PLUGIN_DEFAULT_LEVEL 6

#define ZLIB_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, zlib_storage_module)
#define ZLIB_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, zlib_mail_module)
#define ZLIB_USER_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, zlib_user_module)

#define MAX_INBUF_SIZE (1024*1024)
#define ZLIB_MAIL_CACHE_EXPIRE_MSECS (60*1000)

struct zlib_mail {
	union mail_module_context module_ctx;
	bool verifying_save;
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

static bool zlib_mailbox_is_permail(struct mailbox *box)
{
	enum mail_storage_class_flags class_flags = box->storage->class_flags;

	return (class_flags & MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS) == 0 &&
		(class_flags & MAIL_STORAGE_CLASS_FLAG_BINARY_DATA) != 0;
}

static void zlib_mail_cache_close(struct zlib_user *zuser)
{
	struct zlib_mail_cache *cache = &zuser->cache;

	timeout_remove(&cache->to);
	i_stream_unref(&cache->input);
	i_zero(cache);
}

static struct istream *
zlib_mail_cache_open(struct zlib_user *zuser, struct mail *mail,
		     struct istream *input, bool do_cache)
{
	struct zlib_mail_cache *cache = &zuser->cache;
	struct istream *inputs[2];
	string_t *temp_prefix = t_str_new(128);

	if (do_cache)
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
	i_stream_set_name(input, t_strdup_printf("zlib(%s)",
						 i_stream_get_name(inputs[0])));
	i_stream_unref(&inputs[0]);

	if (do_cache) {
		cache->to = timeout_add(ZLIB_MAIL_CACHE_EXPIRE_MSECS,
					zlib_mail_cache_close, zuser);
		cache->box = mail->box;
		cache->uid = mail->uid;
		cache->input = input;
		/* index-mail wants the stream to be destroyed at close, so create
		   a new stream instead of just increasing reference. */
		return i_stream_create_limit(cache->input, (uoff_t)-1);
	} else {
		return input;
	}
}

static int zlib_istream_opened(struct mail *_mail, struct istream **stream)
{
	struct zlib_user *zuser = ZLIB_USER_CONTEXT(_mail->box->storage->user);
	struct zlib_mail_cache *cache = &zuser->cache;
	struct mail_private *mail = (struct mail_private *)_mail;
	struct zlib_mail *zmail = ZLIB_MAIL_CONTEXT(mail);
	struct istream *input;
	const struct compression_handler *handler;

	if (zmail->verifying_save) {
		/* zlib_mail_save_finish() is verifying that the user-given
		   input doesn't look compressed. */
		return zmail->module_ctx.super.istream_opened(_mail, stream);
	}

	if (_mail->uid > 0 && cache->uid == _mail->uid && cache->box == _mail->box) {
		/* use the cached stream. when doing partial reads it should
		   already be seeked into the wanted offset. */
		i_stream_unref(stream);
		i_stream_seek(cache->input, 0);
		*stream = i_stream_create_limit(cache->input, (uoff_t)-1);
		return zmail->module_ctx.super.istream_opened(_mail, stream);
	}

	handler = compression_detect_handler(*stream);
	if (handler != NULL) {
		if (handler->create_istream == NULL) {
			mail_set_critical(_mail,
				"zlib plugin: Detected %s compression "
				"but support not compiled in", handler->ext);
			return -1;
		}

		input = *stream;
		*stream = handler->create_istream(input, TRUE);
		i_stream_unref(&input);
		/* dont cache the stream if _mail->uid is 0 */
		*stream = zlib_mail_cache_open(zuser, _mail, *stream, (_mail->uid > 0));
	}
	return zmail->module_ctx.super.istream_opened(_mail, stream);
}

static void zlib_mail_close(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct zlib_mail *zmail = ZLIB_MAIL_CONTEXT(mail);
	struct zlib_user *zuser = ZLIB_USER_CONTEXT(_mail->box->storage->user);
	struct zlib_mail_cache *cache = &zuser->cache;
	uoff_t size;

	if (_mail->uid > 0 && cache->uid == _mail->uid && cache->box == _mail->box) {
		/* make sure we have read the entire email into the seekable
		   stream (which causes the original input stream to be
		   unrefed). we can't safely keep the original input stream
		   open after the mail is closed. */
		if (i_stream_get_size(cache->input, TRUE, &size) < 0)
			zlib_mail_cache_close(zuser);
	}
	zmail->module_ctx.super.close(_mail);
}

static void zlib_mail_allocated(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	struct zlib_mail *zmail;

	if (!zlib_mailbox_is_permail(_mail->box))
		return;

	zmail = p_new(mail->pool, struct zlib_mail, 1);
	zmail->module_ctx.super = *v;
	mail->vlast = &zmail->module_ctx.super;

	v->istream_opened = zlib_istream_opened;
	v->close = zlib_mail_close;
	MODULE_CONTEXT_SET(mail, zlib_mail_module, zmail);
}

static int zlib_mail_save_finish(struct mail_save_context *ctx)
{
	struct mailbox *box = ctx->transaction->box;
	union mailbox_module_context *zbox = ZLIB_CONTEXT(box);
	struct mail_private *mail = (struct mail_private *)ctx->dest_mail;
	struct zlib_mail *zmail = ZLIB_MAIL_CONTEXT(mail);
	struct istream *input;
	int ret;

	if (zbox->super.save_finish(ctx) < 0)
		return -1;

	zmail->verifying_save = TRUE;
	ret = mail_get_stream(ctx->dest_mail, NULL, NULL, &input);
	zmail->verifying_save = FALSE;
	if (ret < 0)
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

	if (zuser->save_handler == NULL) {
		v->save_finish = zlib_mail_save_finish;
	} else {
		v->save_begin = zlib_mail_save_compress_begin;
	}
}

static void zlib_mailbox_open_input(struct mailbox *box)
{
	const struct compression_handler *handler;
	struct istream *input;
	struct stat st;
	int fd;

	handler = compression_lookup_handler_from_ext(box->name);
	if (handler == NULL || handler->create_istream == NULL)
		return;

	if (mail_storage_is_mailbox_file(box->storage)) {
		/* looks like a compressed single file mailbox. we should be
		   able to handle this. */
		const char *box_path = mailbox_get_path(box);

		fd = open(box_path, O_RDONLY);
		if (fd == -1) {
			/* let the standard handler figure out what to do
			   with the failure */
			return;
		}
		if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
			i_close_fd(&fd);
			return;
		}
		input = i_stream_create_fd_autoclose(&fd, MAX_INBUF_SIZE);
		i_stream_set_name(input, box_path);
		box->input = handler->create_istream(input, TRUE);
		i_stream_unref(&input);
		box->flags |= MAILBOX_FLAG_READONLY;
	}
}

static int zlib_mailbox_open(struct mailbox *box)
{
	union mailbox_module_context *zbox = ZLIB_CONTEXT(box);

	if (box->input == NULL &&
	    (box->storage->class_flags &
	     MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS) != 0)
		zlib_mailbox_open_input(box);

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

	zbox = p_new(box->pool, union mailbox_module_context, 1);
	zbox->super = *v;
	box->vlast = &zbox->super;
	v->open = zlib_mailbox_open;
	v->close = zlib_mailbox_close;

	MODULE_CONTEXT_SET_SELF(box, zlib_storage_module, zbox);

	if (zlib_mailbox_is_permail(box))
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
	int ret;

	zuser = p_new(user->pool, struct zlib_user, 1);
	zuser->module_ctx.super = *v;
	user->vlast = &zuser->module_ctx.super;
	v->deinit = zlib_mail_user_deinit;

	name = mail_user_plugin_getenv(user, "zlib_save");
	if (name != NULL && *name != '\0') {
		ret = compression_lookup_handler(name, &zuser->save_handler);
		if (ret <= 0) {
			i_error("zlib_save: %s: %s", ret == 0 ?
				"Support not compiled in for handler" :
				"Unknown handler", name);
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
