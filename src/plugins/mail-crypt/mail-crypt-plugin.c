/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

/* FIXME: cache handling could be useful to move to Dovecot core, so that if
   we're using this plugin together with zlib plugin there would be just one
   cache. */

#include "lib.h"
#include "ioloop.h"
#include "randgen.h"
#include "module-dir.h"
#include "str.h"
#include "safe-mkstemp.h"
#include "istream.h"
#include "istream-decrypt.h"
#include "istream-seekable.h"
#include "ostream.h"
#include "ostream-encrypt.h"
#include "mail-user.h"
#include "mail-copy.h"
#include "index-storage.h"
#include "index-mail.h"
#include "mail-crypt-common.h"
#include "mail-crypt-key.h"
#include "mail-crypt-plugin.h"
#include "sha2.h"
#include "dcrypt-iostream.h"
#include "hex-binary.h"

struct mail_crypt_mailbox {
	union mailbox_module_context module_ctx;
	struct dcrypt_public_key *pub_key;
};

const char *mail_crypt_plugin_version = DOVECOT_ABI_VERSION;

#define MAIL_CRYPT_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, mail_crypt_mail_module)
#define MAIL_CRYPT_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, mail_crypt_storage_module)
#define MAIL_CRYPT_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mail_crypt_user_module)
#define MAIL_CRYPT_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, mail_crypt_user_module)

static MODULE_CONTEXT_DEFINE_INIT(mail_crypt_user_module,
				  &mail_user_module_register);
static MODULE_CONTEXT_DEFINE_INIT(mail_crypt_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(mail_crypt_mail_module,
				  &mail_module_register);

struct mail_crypt_user *mail_crypt_get_mail_crypt_user(struct mail_user *user)
{
	return MAIL_CRYPT_USER_CONTEXT(user);
}

static bool mail_crypt_is_stream_encrypted(struct istream *input)
{
	const unsigned char *data = NULL;
	size_t size;

	if (i_stream_read_data(input, &data, &size,
				sizeof(IOSTREAM_CRYPT_MAGIC)) <= 0) {
		return FALSE;
	}

	if (memcmp(data, IOSTREAM_CRYPT_MAGIC,
		      sizeof(IOSTREAM_CRYPT_MAGIC)) != 0) {
		return FALSE;
	}
	return TRUE;
}

static void mail_crypt_cache_close(struct mail_crypt_user *muser)
{
	struct mail_crypt_cache *cache = &muser->cache;

	timeout_remove(&cache->to);
	i_stream_unref(&cache->input);
	i_zero(cache);
}

static struct istream *
mail_crypt_cache_open(struct mail_crypt_user *muser, struct mail *mail,
		      struct istream *input)
{
	struct mail_crypt_cache *cache = &muser->cache;
	struct istream *inputs[2];
	string_t *temp_prefix = t_str_new(128);

	mail_crypt_cache_close(muser);

	input->seekable = FALSE;
	inputs[0] = input;
	inputs[1] = NULL;
	mail_user_set_get_temp_prefix(temp_prefix, mail->box->storage->user->set);
	input = i_stream_create_seekable_path(inputs,
				i_stream_get_max_buffer_size(inputs[0]),
				str_c(temp_prefix));
	i_stream_unref(&inputs[0]);

	if (mail->uid > 0) {
		cache->to = timeout_add(MAIL_CRYPT_MAIL_CACHE_EXPIRE_MSECS,
				mail_crypt_cache_close, muser);
		cache->box = mail->box;
		cache->uid = mail->uid;
		cache->input = input;
		/* index-mail wants the stream to be destroyed at close, so create
		   a new stream instead of just increasing reference. */
		return i_stream_create_limit(cache->input, (uoff_t)-1);
	}

	return input;
}

static int mail_crypt_istream_get_private_key(const char *pubkey_digest,
			   struct dcrypt_private_key **priv_key_r,
			   const char **error_r,
			   void *context)
{
	/* mailbox_crypt_search_all_private_keys requires error_r != NULL */
	i_assert(error_r != NULL);
	int ret;
	struct mail *_mail = context;
	struct mail_crypt_user *muser =
		MAIL_CRYPT_USER_CONTEXT_REQUIRE(_mail->box->storage->user);

	*priv_key_r = mail_crypt_global_key_find(&muser->global_keys,
						 pubkey_digest);
	if (*priv_key_r != NULL) return 1;

	struct mail_namespace *ns = mailbox_get_namespace(_mail->box);

	if (ns->type == MAIL_NAMESPACE_TYPE_SHARED) {
		ret = mail_crypt_box_get_shared_key(_mail->box, pubkey_digest,
						    priv_key_r, error_r);
	} else if (ns->type != MAIL_NAMESPACE_TYPE_PUBLIC) {
		ret = mail_crypt_get_private_key(_mail->box, pubkey_digest,
						 FALSE, FALSE, priv_key_r,
						 error_r);
	} else {
		*error_r = "Public emails cannot have keys";
		ret = -1;
	}

	i_assert(ret <= 0 || *priv_key_r != NULL);

	return ret;
}

static int
mail_crypt_istream_opened(struct mail *_mail, struct istream **stream)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_user *user = _mail->box->storage->user;
	struct mail_crypt_user *muser = MAIL_CRYPT_USER_CONTEXT_REQUIRE(user);
	struct mail_crypt_cache *cache = &muser->cache;
	union mail_module_context *mmail = MAIL_CRYPT_MAIL_CONTEXT(mail);
	struct istream *input;

	if (_mail->uid > 0 && cache->uid == _mail->uid && cache->box == _mail->box) {
		/* use the cached stream. when doing partial reads it should
		   already be seeked into the wanted offset. */
		i_stream_unref(stream);
		i_stream_seek(cache->input, 0);
		*stream = i_stream_create_limit(cache->input, (uoff_t)-1);
		return mmail->super.istream_opened(_mail, stream);
	}

	/* decryption is the outmost stream, so add it before others
	   (e.g. zlib) */
	if (!mail_crypt_is_stream_encrypted(*stream))
		return mmail->super.istream_opened(_mail, stream);

	input = *stream;
	*stream = i_stream_create_decrypt_callback(input,
				mail_crypt_istream_get_private_key, _mail);
	i_stream_unref(&input);

	*stream = mail_crypt_cache_open(muser, _mail, *stream);
	return mmail->super.istream_opened(_mail, stream);
}

static void mail_crypt_close(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *mmail = MAIL_CRYPT_MAIL_CONTEXT(mail);
	struct mail_crypt_user *muser =
		MAIL_CRYPT_USER_CONTEXT_REQUIRE(_mail->box->storage->user);
	struct mail_crypt_cache *cache = &muser->cache;
	uoff_t size;

	if (_mail->uid > 0 && cache->uid == _mail->uid && cache->box == _mail->box) {
		/* make sure we have read the entire email into the seekable
		   stream (which causes the original input stream to be
		   unrefed). we can't safely keep the original input stream
		   open after the mail is closed. */
		if (i_stream_get_size(cache->input, TRUE, &size) < 0)
			mail_crypt_cache_close(muser);
	}
	mmail->super.close(_mail);
}

static void mail_crypt_mail_allocated(struct mail *_mail)
{
	struct mail_crypt_user *muser =
		MAIL_CRYPT_USER_CONTEXT(_mail->box->storage->user);
	if (muser == NULL) return;

	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *mmail;

	mmail = p_new(mail->pool, union mail_module_context, 1);
	mmail->super = *v;
	mail->vlast = &mmail->super;

	v->istream_opened = mail_crypt_istream_opened;
	v->close = mail_crypt_close;
	MODULE_CONTEXT_SET_SELF(mail, mail_crypt_mail_module, mmail);
}

static int mail_crypt_mail_save_finish(struct mail_save_context *ctx)
{
	struct mailbox *box = ctx->transaction->box;
	union mailbox_module_context *zbox = MAIL_CRYPT_CONTEXT(box);
	struct istream *input;

	if (zbox->super.save_finish(ctx) < 0)
		return -1;

	/* we're here only if mail-crypt plugin is disabled. we want to make
	   sure that even though we're saving an unencrypted mail, the mail
	   can't be faked to look like an encrypted mail. */
	if (mail_get_stream(ctx->dest_mail, NULL, NULL, &input) < 0)
		return -1;

	if (mail_crypt_is_stream_encrypted(input)) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			"Saving mails encrypted by client isn't supported");
		return -1;
	}
	return 0;
}

static int
mail_crypt_mail_save_begin(struct mail_save_context *ctx,
			   struct istream *input)
{
	const char *pubid;
	struct mailbox *box = ctx->transaction->box;
	struct mail_crypt_mailbox *mbox = MAIL_CRYPT_CONTEXT(box);
	struct mail_crypt_user *muser =
		MAIL_CRYPT_USER_CONTEXT_REQUIRE(box->storage->user);

	enum io_stream_encrypt_flags enc_flags;
	if (muser->save_version == 1) {
		enc_flags = IO_STREAM_ENC_VERSION_1;
	} else if (muser->save_version == 2) {
		enc_flags = IO_STREAM_ENC_INTEGRITY_AEAD;
	} else {
		i_assert(muser->save_version == 0);
		i_panic("mail_crypt_mail_save_begin not supposed to be called"
				"when mail_crypt_save_version is 0");
	}

	if (mbox->module_ctx.super.save_begin(ctx, input) < 0)
		return -1;

	struct dcrypt_public_key *pub_key;
	if (muser->global_keys.public_key != NULL)
		pub_key = muser->global_keys.public_key;
	else if (mbox->pub_key != NULL)
		pub_key = mbox->pub_key;
	else {
		const char *error;
		int ret;

		if ((ret = mail_crypt_box_get_public_key(box, &pub_key,
							 &error)) <= 0)
		{
			struct dcrypt_keypair pair;

			if (ret < 0) {
				mail_storage_set_error(box->storage,
					MAIL_ERROR_PARAMS,
					t_strdup_printf("get_public_key(%s) failed: %s",
							mailbox_get_vname(box),
							error));
				return ret;
			}

			if (muser->save_version < 2) {
				mail_storage_set_error(box->storage,
                                        MAIL_ERROR_PARAMS,
                                        t_strdup_printf("generate_keypair(%s) failed: "
                                                        "unsupported save_version=%d",
                                                        mailbox_get_vname(box),
                                                        muser->save_version));
                                return -1;
			}

			if (mail_crypt_box_generate_keypair(box, &pair, NULL,
							    &pubid, &error) < 0) {
				mail_storage_set_error(box->storage,
					MAIL_ERROR_PARAMS,
					t_strdup_printf("generate_keypair(%s) failed: %s",
							mailbox_get_vname(box),
							error));
				return -1;
			}
			pub_key = pair.pub;
			dcrypt_key_unref_private(&pair.priv);

		}
		mbox->pub_key = pub_key;
	}

	/* encryption is the outermost layer (zlib etc. are inside) */
	struct ostream *output = o_stream_create_encrypt(ctx->data.output,
			MAIL_CRYPT_ENC_ALGORITHM, pub_key, enc_flags);

	o_stream_unref(&ctx->data.output);
	ctx->data.output = output;
	o_stream_cork(ctx->data.output);
	return 0;
}

static int
mail_crypt_mailbox_copy(struct mail_save_context *ctx, struct mail *mail)
{
	struct mail_crypt_mailbox *mbox = MAIL_CRYPT_CONTEXT(ctx->transaction->box);

	if (ctx->transaction->box != mail->box)
		return mail_storage_copy(ctx, mail);
	return mbox->module_ctx.super.copy(ctx, mail);
}

static void mail_crypt_mailbox_close(struct mailbox *box)
{
	struct mail_crypt_mailbox *mbox = MAIL_CRYPT_CONTEXT(box);
	struct mail_crypt_user *muser =
		MAIL_CRYPT_USER_CONTEXT_REQUIRE(box->storage->user);

	if (mbox->pub_key != NULL)
		dcrypt_key_unref_public(&mbox->pub_key);
	if (muser != NULL && muser->cache.box == box)
		mail_crypt_cache_close(muser);
	mbox->module_ctx.super.close(box);
}

static void mail_crypt_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct mail_crypt_user *muser =
		MAIL_CRYPT_USER_CONTEXT(box->storage->user);
	struct mail_crypt_mailbox *mbox;
	enum mail_storage_class_flags class_flags = box->storage->class_flags;

	mbox = p_new(box->pool, struct mail_crypt_mailbox, 1);
	mbox->module_ctx.super = *v;
	box->vlast = &mbox->module_ctx.super;
	v->close = mail_crypt_mailbox_close;

	MODULE_CONTEXT_SET(box, mail_crypt_storage_module, mbox);

	if ((class_flags & MAIL_STORAGE_CLASS_FLAG_BINARY_DATA) != 0) {
		if (muser != NULL) {
			if (muser->save_version > 0) {
				v->save_begin = mail_crypt_mail_save_begin;
				/* if global keys are used, re-encrypting on copy/move
				   is not necessary, so do not attempt to do it.

				   with per-folder keys, emails must be re-encrypted
				   when moving to another folder */
				if (muser->global_keys.public_key == NULL)
					v->copy = mail_crypt_mailbox_copy;
			}
		} else {
			v->save_finish = mail_crypt_mail_save_finish;
		}
	}
}

static void mail_crypt_mail_user_deinit(struct mail_user *user)
{
	struct mail_crypt_user *muser = MAIL_CRYPT_USER_CONTEXT_REQUIRE(user);

	mail_crypt_key_cache_destroy(&muser->key_cache);
	mail_crypt_global_keys_free(&muser->global_keys);
	mail_crypt_cache_close(muser);
	muser->module_ctx.super.deinit(user);
}

static void mail_crypt_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct mail_crypt_user *muser;
	const char *error = NULL;

	muser = p_new(user->pool, struct mail_crypt_user, 1);
	muser->module_ctx.super = *v;
	user->vlast = &muser->module_ctx.super;

	const char *curve = mail_user_plugin_getenv(user, "mail_crypt_curve");
	buffer_t *tmp = t_str_new(64);
	if (curve == NULL || *curve == '\0') {
		e_debug(user->event, "mail_crypt_plugin: mail_crypt_curve setting "
			"missing - generating EC keys disabled");
	} else if (!dcrypt_name2oid(curve, tmp, &error)) {
		user->error = p_strdup_printf(user->pool,
			"mail_crypt_plugin: "
			"invalid mail_crypt_curve setting %s: %s - "
			"plugin disabled",
			curve, error);
	} else {
		muser->curve = p_strdup(user->pool, curve);
	}

	const char *version = mail_user_plugin_getenv(user,
			"mail_crypt_save_version");

	if (version == NULL || *version == '\0') {
		user->error = p_strdup_printf(user->pool,
				"mail_crypt_plugin: "
				"mail_crypt_save_version setting missing "
				"- plugin disabled");
	} else if (version[0] == '0') {
		muser->save_version = 0;
	} else if (version[0] == '1') {
		muser->save_version = 1;
	} else if (version[0] == '2') {
		muser->save_version = 2;
	} else {
		user->error = p_strdup_printf(user->pool,
				"mail_crypt_plugin: Invalid "
				"mail_crypt_save_version %s: use 0, 1, or 2 ",
				version);
	}

	if (mail_crypt_global_keys_load(user, "mail_crypt_global",
					&muser->global_keys, FALSE, &error) < 0) {
		user->error = p_strdup_printf(user->pool,
				"mail_crypt_plugin: %s", error);
	}

	v->deinit = mail_crypt_mail_user_deinit;
	MODULE_CONTEXT_SET(user, mail_crypt_user_module, muser);
}

static struct mail_storage_hooks mail_crypt_mail_storage_hooks = {
	.mail_user_created = mail_crypt_mail_user_created,
	.mail_allocated = mail_crypt_mail_allocated
};

static struct mail_storage_hooks mail_crypt_mail_storage_hooks_post = {
	.mailbox_allocated = mail_crypt_mailbox_allocated
};

static struct module crypto_post_module = {
	.path = "lib95_mail_crypt_plugin.so"
};

void mail_crypt_plugin_init(struct module *module)
{
	const char* error;
	if (!dcrypt_initialize("openssl", NULL, &error))
		i_fatal("dcrypt_initialize(): %s", error);
	mail_storage_hooks_add(module, &mail_crypt_mail_storage_hooks);
	/* rather kludgy. we need to hook into mail reading as early as
	   possible, but we need to hook into mail writing as late as
	   possible. we could create just two real plugins, but that's a bit
	   annoying to configure. */
	mail_storage_hooks_add_forced(&crypto_post_module,
				      &mail_crypt_mail_storage_hooks_post);
	mail_crypt_key_register_mailbox_internal_attributes();
}

void mail_crypt_plugin_deinit(void)
{
	mail_storage_hooks_remove(&mail_crypt_mail_storage_hooks);
	mail_storage_hooks_remove(&mail_crypt_mail_storage_hooks_post);
}
