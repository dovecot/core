/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "seq-range-array.h"
#include "maildir-storage.h"
#include "mail-namespace.h"
#include "lazy-expunge-plugin.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>

#define LAZY_EXPUNGE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lazy_expunge_mail_storage_module)
#define LAZY_EXPUNGE_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lazy_expunge_mailbox_list_module)

enum lazy_namespace {
	LAZY_NAMESPACE_EXPUNGE,
	LAZY_NAMESPACE_DELETE,
	LAZY_NAMESPACE_DELETE_EXPUNGE,

	LAZY_NAMESPACE_COUNT
};

struct lazy_expunge_mailbox_list {
	union mailbox_list_module_context module_ctx;

	struct mail_storage *storage;
};

struct lazy_expunge_mail_storage {
	union mail_storage_module_context module_ctx;

	bool internal_namespace;
};

struct lazy_expunge_transaction {
	union mailbox_transaction_module_context module_ctx;

	ARRAY_TYPE(seq_range) expunge_seqs;
	struct mailbox *expunge_box;

	bool failed;
};

const char *lazy_expunge_plugin_version = PACKAGE_VERSION;

static void (*lazy_expunge_next_hook_mail_namespaces_created)
	(struct mail_namespace *namespaces);
static void (*lazy_expunge_next_hook_mail_storage_created)
	(struct mail_storage *storage);
static void (*lazy_expunge_next_hook_mailbox_list_created)
	(struct mailbox_list *list);

static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mail_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mail_module,
				  &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mailbox_list_module,
				  &mailbox_list_module_register);

static struct mail_namespace *lazy_namespaces[LAZY_NAMESPACE_COUNT];

static struct mailbox *
mailbox_open_or_create(struct mail_storage *storage, const char *name)
{
	struct mailbox *box;
	enum mail_error error;

	box = mailbox_open(storage, name, NULL, MAILBOX_OPEN_FAST |
			   MAILBOX_OPEN_KEEP_RECENT |
			   MAILBOX_OPEN_NO_INDEX_FILES);
	if (box != NULL)
		return box;

	(void)mail_storage_get_last_error(storage, &error);
	if (error != MAIL_ERROR_NOTFOUND)
		return NULL;

	/* try creating it. */
	if (mail_storage_mailbox_create(storage, name, FALSE) < 0)
		return NULL;

	/* and try opening again */
	box = mailbox_open(storage, name, NULL, MAILBOX_OPEN_FAST |
			   MAILBOX_OPEN_KEEP_RECENT);
	return box;
}

static void lazy_expunge_mail_expunge(struct mail *_mail)
{
	struct lazy_expunge_transaction *lt =
		LAZY_EXPUNGE_CONTEXT(_mail->transaction);
	struct mail_storage *deststorage;

	if (lt->expunge_box == NULL) {
		deststorage = lazy_namespaces[LAZY_NAMESPACE_EXPUNGE]->storage;
		lt->expunge_box = mailbox_open_or_create(deststorage,
							 _mail->box->name);
		if (lt->expunge_box == NULL) {
			mail_storage_set_critical(_mail->box->storage,
				"lazy_expunge: Couldn't open expunge mailbox");
			lt->failed = TRUE;
			return;
		}
	}

	seq_range_array_add(&lt->expunge_seqs, 32, _mail->uid);
}

static struct mailbox_transaction_context *
lazy_expunge_transaction_begin(struct mailbox *box,
			       enum mailbox_transaction_flags flags)
{
	union mailbox_module_context *mbox = LAZY_EXPUNGE_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct lazy_expunge_transaction *lt;

	t = mbox->super.transaction_begin(box, flags);
	lt = i_new(struct lazy_expunge_transaction, 1);

	MODULE_CONTEXT_SET(t, lazy_expunge_mail_storage_module, lt);
	return t;
}

struct lazy_expunge_move_context {
	string_t *path;
	unsigned int dir_len;
};

static int lazy_expunge_move(struct maildir_mailbox *mbox,
			     const char *path, void *context)
{
	struct lazy_expunge_move_context *ctx = context;
	const char *p;

	str_truncate(ctx->path, ctx->dir_len);
	p = strrchr(path, '/');
	str_append(ctx->path, p == NULL ? path : p + 1);

	if (rename(path, str_c(ctx->path)) == 0)
		return 1;
	if (errno == ENOENT)
		return 0;
	mail_storage_set_critical(mbox->ibox.box.storage,
				  "rename(%s, %s) failed: %m",
				  path, str_c(ctx->path));
	return -1;
}

static int lazy_expunge_move_expunges(struct mailbox *srcbox,
				      struct lazy_expunge_transaction *lt)
{
	struct maildir_mailbox *msrcbox = (struct maildir_mailbox *)srcbox;
	struct mailbox_transaction_context *trans;
	struct index_transaction_context *itrans;
	struct lazy_expunge_move_context ctx;
	const struct seq_range *range;
	unsigned int i, count;
	const char *dir;
	uint32_t seq, uid, seq1, seq2;
	bool is_file;
	int ret = 0;

	dir = mail_storage_get_mailbox_path(lt->expunge_box->storage,
					    lt->expunge_box->name, &is_file);
	dir = t_strconcat(dir, "/cur/", NULL);

	ctx.path = str_new(default_pool, 256);
	str_append(ctx.path, dir);
	ctx.dir_len = str_len(ctx.path);

	trans = mailbox_transaction_begin(srcbox,
					  MAILBOX_TRANSACTION_FLAG_EXTERNAL);
	itrans = (struct index_transaction_context *)trans;

	range = array_get(&lt->expunge_seqs, &count);
	for (i = 0; i < count && ret == 0; i++) {
		mailbox_get_seq_range(srcbox, range[i].seq1, range[i].seq2,
				      &seq1, &seq2);
		for (uid = range[i].seq1; uid <= range[i].seq2; uid++) {
			if (maildir_file_do(msrcbox, uid, lazy_expunge_move,
					    &ctx) < 0) {
				ret = -1;
				break;
			}
		}
		for (seq = seq1; seq <= seq2; seq++)
			mail_index_expunge(itrans->trans, seq);
	}

	if (mailbox_transaction_commit(&trans) < 0)
		ret = -1;

	str_free(&ctx.path);
	return ret;
}

static void lazy_expunge_transaction_free(struct lazy_expunge_transaction *lt)
{
	if (lt->expunge_box != NULL)
		mailbox_close(&lt->expunge_box);
	if (array_is_created(&lt->expunge_seqs))
		array_free(&lt->expunge_seqs);
	i_free(lt);
}

static int
lazy_expunge_transaction_commit(struct mailbox_transaction_context *ctx,
				uint32_t *uid_validity_r,
				uint32_t *first_saved_uid_r,
				uint32_t *last_saved_uid_r)
{
	union mailbox_module_context *mbox = LAZY_EXPUNGE_CONTEXT(ctx->box);
	struct lazy_expunge_transaction *lt = LAZY_EXPUNGE_CONTEXT(ctx);
	struct mailbox *srcbox = ctx->box;
	int ret;

	if (lt->failed) {
		mbox->super.transaction_rollback(ctx);
		ret = -1;
	} else {
		ret = mbox->super.transaction_commit(ctx, uid_validity_r,
						     first_saved_uid_r,
						     last_saved_uid_r);
	}

	if (ret == 0 && array_is_created(&lt->expunge_seqs))
		ret = lazy_expunge_move_expunges(srcbox, lt);

	lazy_expunge_transaction_free(lt);
	return ret;
}

static void
lazy_expunge_transaction_rollback(struct mailbox_transaction_context *ctx)
{
	union mailbox_module_context *mbox = LAZY_EXPUNGE_CONTEXT(ctx->box);
	struct lazy_expunge_transaction *lt = LAZY_EXPUNGE_CONTEXT(ctx);

	mbox->super.transaction_rollback(ctx);
	lazy_expunge_transaction_free(lt);
}

static struct mail *
lazy_expunge_mail_alloc(struct mailbox_transaction_context *t,
			enum mail_fetch_field wanted_fields,
			struct mailbox_header_lookup_ctx *wanted_headers)
{
	union mailbox_module_context *mbox = LAZY_EXPUNGE_CONTEXT(t->box);
	union mail_module_context *mmail;
	struct mail *_mail;
	struct mail_private *mail;

	_mail = mbox->super.mail_alloc(t, wanted_fields, wanted_headers);
	mail = (struct mail_private *)_mail;

	mmail = p_new(mail->pool, union mail_module_context, 1);
	mmail->super = mail->v;

	mail->v.expunge = lazy_expunge_mail_expunge;
	MODULE_CONTEXT_SET_SELF(mail, lazy_expunge_mail_module, mmail);
	return _mail;
}

static struct mailbox *
lazy_expunge_mailbox_open(struct mail_storage *storage, const char *name,
			  struct istream *input, enum mailbox_open_flags flags)
{
	struct lazy_expunge_mail_storage *lstorage =
		LAZY_EXPUNGE_CONTEXT(storage);
	struct mailbox *box;
	union mailbox_module_context *mbox;

	box = lstorage->module_ctx.super.
		mailbox_open(storage, name, input, flags);
	if (box == NULL || lstorage->internal_namespace)
		return box;

	mbox = p_new(box->pool, union mailbox_module_context, 1);
	mbox->super = box->v;

	box->v.transaction_begin = lazy_expunge_transaction_begin;
	box->v.transaction_commit = lazy_expunge_transaction_commit;
	box->v.transaction_rollback = lazy_expunge_transaction_rollback;
	box->v.mail_alloc = lazy_expunge_mail_alloc;
	MODULE_CONTEXT_SET_SELF(box, lazy_expunge_mail_storage_module, mbox);
	return box;
}

static int dir_move_or_merge(struct mailbox_list *list,
			     const char *srcdir, const char *destdir)
{
	DIR *dir;
	struct dirent *dp;
	string_t *src_path, *dest_path;
	unsigned int src_dirlen, dest_dirlen;
	int ret = 0;

	if (rename(srcdir, destdir) == 0 || errno == ENOENT)
		return 0;

	if (!EDESTDIREXISTS(errno)) {
		mailbox_list_set_critical(list,
			"rename(%s, %s) failed: %m", srcdir, destdir);
	}

	/* rename all the files separately */
	dir = opendir(srcdir);
	if (dir == NULL) {
		mailbox_list_set_critical(list,
			"opendir(%s) failed: %m", srcdir);
		return -1;
	}

	src_path = t_str_new(512);
	dest_path = t_str_new(512);

	str_append(src_path, srcdir);
	str_append(dest_path, destdir);
	str_append_c(src_path, '/');
	str_append_c(dest_path, '/');
	src_dirlen = str_len(src_path);
	dest_dirlen = str_len(dest_path);

	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_name[0] == '.' &&
		    (dp->d_name[1] == '\0' ||
		     (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))
			continue;

		str_truncate(src_path, src_dirlen);
		str_append(src_path, dp->d_name);
		str_truncate(dest_path, dest_dirlen);
		str_append(dest_path, dp->d_name);

		if (rename(str_c(src_path), str_c(dest_path)) < 0 &&
		    errno != ENOENT) {
			mailbox_list_set_critical(list,
				"rename(%s, %s) failed: %m",
				str_c(src_path), str_c(dest_path));
			ret = -1;
		}
	}
	if (closedir(dir) < 0) {
		mailbox_list_set_critical(list,
			"closedir(%s) failed: %m", srcdir);
		ret = -1;
	}
	if (ret == 0) {
		if (rmdir(srcdir) < 0) {
			mailbox_list_set_critical(list,
				"rmdir(%s) failed: %m", srcdir);
			ret = -1;
		}
	}
	return ret;
}

static int
mailbox_move(struct mailbox_list *src_list, const char *src_name,
	     struct mailbox_list *dest_list, const char **_dest_name)
{
	const char *dest_name = *_dest_name;
	const char *srcdir, *src2dir, *src3dir, *destdir;

	srcdir = mailbox_list_get_path(src_list, src_name,
				       MAILBOX_LIST_PATH_TYPE_MAILBOX);
	destdir = mailbox_list_get_path(dest_list, dest_name,
					MAILBOX_LIST_PATH_TYPE_MAILBOX);
	while (rename(srcdir, destdir) < 0) {
		if (errno == ENOENT)
			return 0;

		if (!EDESTDIREXISTS(errno)) {
			mailbox_list_set_critical(src_list,
				"rename(%s, %s) failed: %m", srcdir, destdir);
			return -1;
		}

		/* mailbox is being deleted multiple times per second.
		   update the filename. */
		dest_name = t_strdup_printf("%s-%04u", *_dest_name,
					    (uint32_t)random());
		destdir = mailbox_list_get_path(dest_list, dest_name,
						MAILBOX_LIST_PATH_TYPE_MAILBOX);
	}

	src2dir = mailbox_list_get_path(src_list, src_name,
					MAILBOX_LIST_PATH_TYPE_CONTROL);
	if (strcmp(src2dir, srcdir) != 0) {
		destdir = mailbox_list_get_path(dest_list, dest_name,
						MAILBOX_LIST_PATH_TYPE_CONTROL);
		(void)dir_move_or_merge(src_list, src2dir, destdir);
	}
	src3dir = mailbox_list_get_path(src_list, src_name,
					MAILBOX_LIST_PATH_TYPE_INDEX);
	if (strcmp(src3dir, srcdir) != 0 && strcmp(src3dir, src2dir) != 0) {
		destdir = mailbox_list_get_path(dest_list, dest_name,
						MAILBOX_LIST_PATH_TYPE_INDEX);
		(void)dir_move_or_merge(src_list, src3dir, destdir);
	}

	*_dest_name = dest_name;
	return 1;
}

static int
lazy_expunge_mailbox_list_delete(struct mailbox_list *list, const char *name)
{
	struct lazy_expunge_mailbox_list *llist =
		LAZY_EXPUNGE_LIST_CONTEXT(list);
	struct lazy_expunge_mail_storage *lstorage;
	struct mailbox_list *dest_list;
	enum mailbox_name_status status;
	const char *destname;
	struct tm *tm;
	char timestamp[256];
	int ret;

	if (llist->storage == NULL) {
		/* not a maildir storage */
		return llist->module_ctx.super.delete_mailbox(list, name);
	}

	lstorage = LAZY_EXPUNGE_CONTEXT(llist->storage);
	if (lstorage->internal_namespace)
		return llist->module_ctx.super.delete_mailbox(list, name);

	/* first do the normal sanity checks */
	if (strcmp(name, "INBOX") == 0) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
				       "INBOX can't be deleted.");
		return -1;
	}

	if (mailbox_list_get_mailbox_name_status(list, name, &status) < 0)
		return -1;
	if (status == MAILBOX_NAME_INVALID) {
		mailbox_list_set_error(list, MAIL_ERROR_PARAMS,
				       "Invalid mailbox name");
		return -1;
	}

	/* destination mailbox name needs to contain a timestamp */
	tm = localtime(&ioloop_time);
	if (strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", tm) == 0)
		i_strocpy(timestamp, dec2str(ioloop_time), sizeof(timestamp));
	destname = t_strconcat(name, "-", timestamp, NULL);

	/* first move the actual mailbox */
	dest_list = lazy_namespaces[LAZY_NAMESPACE_DELETE]->storage->list;
	if ((ret = mailbox_move(list, name, dest_list, &destname)) < 0)
		return -1;
	if (ret == 0) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		return -1;
	}

	/* next move the expunged messages mailbox, if it exists */
	list = lazy_namespaces[LAZY_NAMESPACE_EXPUNGE]->storage->list;
	dest_list =
		lazy_namespaces[LAZY_NAMESPACE_DELETE_EXPUNGE]->storage->list;
	(void)mailbox_move(list, name, dest_list, &destname);
	return 0;
}

static void lazy_expunge_mail_storage_init(struct mail_storage *storage)
{
	struct lazy_expunge_mailbox_list *llist =
		LAZY_EXPUNGE_LIST_CONTEXT(storage->list);
	struct lazy_expunge_mail_storage *lstorage;
	const char *const *p;
	unsigned int i;

	/* if this is one of our internal storages, mark it as such before
	   quota plugin sees it */
	p = t_strsplit_spaces(getenv("LAZY_EXPUNGE"), " ");
	for (i = 0; i < LAZY_NAMESPACE_COUNT; i++, p++) {
		if (strcmp(storage->ns->prefix, *p) == 0) {
			storage->ns->flags |= NAMESPACE_FLAG_INTERNAL;
			break;
		}
	}

	llist->storage = storage;

	lstorage = p_new(storage->pool, struct lazy_expunge_mail_storage, 1);
	lstorage->module_ctx.super = storage->v;
	storage->v.mailbox_open = lazy_expunge_mailbox_open;

	MODULE_CONTEXT_SET(storage, lazy_expunge_mail_storage_module, lstorage);
}

static void lazy_expunge_mail_storage_created(struct mail_storage *storage)
{
	/* only maildir supported for now */
	if (strcmp(storage->name, "maildir") == 0)
		lazy_expunge_mail_storage_init(storage);

	if (lazy_expunge_next_hook_mail_storage_created != NULL)
		lazy_expunge_next_hook_mail_storage_created(storage);
}

static void lazy_expunge_mailbox_list_created(struct mailbox_list *list)
{
	struct lazy_expunge_mailbox_list *llist;

	if (lazy_expunge_next_hook_mailbox_list_created != NULL)
		lazy_expunge_next_hook_mailbox_list_created(list);

	llist = p_new(list->pool, struct lazy_expunge_mailbox_list, 1);
	llist->module_ctx.super = list->v;
	list->v.delete_mailbox = lazy_expunge_mailbox_list_delete;

	MODULE_CONTEXT_SET(list, lazy_expunge_mailbox_list_module, llist);
}

static void
lazy_expunge_hook_mail_namespaces_created(struct mail_namespace *namespaces)
{
	struct lazy_expunge_mail_storage *lstorage;
	const char *const *p;
	int i;

	if (lazy_expunge_next_hook_mail_namespaces_created != NULL)
		lazy_expunge_next_hook_mail_namespaces_created(namespaces);

	p = t_strsplit_spaces(getenv("LAZY_EXPUNGE"), " ");
	for (i = 0; i < LAZY_NAMESPACE_COUNT; i++, p++) {
		const char *name = *p;

		if (name == NULL)
			i_fatal("lazy_expunge: Missing namespace #%d", i + 1);

		lazy_namespaces[i] =
			mail_namespace_find_prefix(namespaces, name);
		if (lazy_namespaces[i] == NULL)
			i_fatal("lazy_expunge: Unknown namespace: '%s'", name);
		if (strcmp(lazy_namespaces[i]->storage->name, "maildir") != 0) {
			i_fatal("lazy_expunge: Namespace must be in maildir "
				"format: %s", name);
		}

		/* we don't want to override these namespaces' expunge/delete
		   operations. */
		lstorage = LAZY_EXPUNGE_CONTEXT(lazy_namespaces[i]->storage);
		lstorage->internal_namespace = TRUE;
	}
}

void lazy_expunge_plugin_init(void)
{
	if (getenv("LAZY_EXPUNGE") == NULL)
		return;

	lazy_expunge_next_hook_mail_namespaces_created =
		hook_mail_namespaces_created;
	hook_mail_namespaces_created =
		lazy_expunge_hook_mail_namespaces_created;

	lazy_expunge_next_hook_mail_storage_created = hook_mail_storage_created;
	hook_mail_storage_created = lazy_expunge_mail_storage_created;

	lazy_expunge_next_hook_mailbox_list_created = hook_mailbox_list_created;
	hook_mailbox_list_created = lazy_expunge_mailbox_list_created;
}

void lazy_expunge_plugin_deinit(void)
{
	if (getenv("LAZY_EXPUNGE") == NULL)
		return;

	hook_mail_namespaces_created =
		lazy_expunge_hook_mail_namespaces_created;
	hook_mail_storage_created = lazy_expunge_next_hook_mail_storage_created;
	hook_mailbox_list_created = lazy_expunge_next_hook_mailbox_list_created;
}
