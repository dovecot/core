/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "ioloop.h"
#include "net.h"
#include "write-full.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "notify-plugin.h"
#include "replication-common.h"
#include "replication-plugin.h"


#define REPLICATION_SOCKET_NAME "replication-notify"
#define REPLICATION_FIFO_NAME "replication-notify-fifo"
#define REPLICATION_NOTIFY_DELAY_MSECS 500
#define REPLICATION_SYNC_TIMEOUT_SECS 10

#define REPLICATION_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, replication_user_module)

struct replication_user {
	union mail_user_module_context module_ctx;

	const char *socket_path;

	struct timeout *to;
	enum replication_priority priority;
	unsigned int sync_secs;
};

struct replication_mail_txn_context {
	struct mail_namespace *ns;
	bool new_messages;
	bool sync_trans;
	char *reason;
};

static MODULE_CONTEXT_DEFINE_INIT(replication_user_module,
				  &mail_user_module_register);
static int fifo_fd;
static bool fifo_failed;
static char *fifo_path;

static int
replication_fifo_notify(struct mail_user *user,
			enum replication_priority priority)
{
	string_t *str;
	ssize_t ret;

	if (fifo_failed)
		return -1;
	if (fifo_fd == -1) {
		fifo_fd = open(fifo_path, O_WRONLY | O_NONBLOCK);
		if (fifo_fd == -1) {
			i_error("open(%s) failed: %m", fifo_path);
			fifo_failed = TRUE;
			return -1;
		}
	}
	/* <username> \t <priority> */
	str = t_str_new(256);
	str_append_tabescaped(str, user->username);
	str_append_c(str, '\t');
	switch (priority) {
	case REPLICATION_PRIORITY_NONE:
	case REPLICATION_PRIORITY_SYNC:
		i_unreached();
	case REPLICATION_PRIORITY_LOW:
		str_append(str, "low");
		break;
	case REPLICATION_PRIORITY_HIGH:
		str_append(str, "high");
		break;
	}
	str_append_c(str, '\n');
	ret = write(fifo_fd, str_data(str), str_len(str));
	i_assert(ret != 0);
	if (ret != (ssize_t)str_len(str)) {
		if (ret > 0)
			i_error("write(%s) wrote partial data", fifo_path);
		else if (errno == EAGAIN) {
			/* busy, try again later */
			return 0;
		} else if (errno != EPIPE) {
			i_error("write(%s) failed: %m", fifo_path);
		} else {
			/* server was probably restarted, don't bother logging
			   this. */
		}
		if (close(fifo_fd) < 0)
			i_error("close(%s) failed: %m", fifo_path);
		fifo_fd = -1;
		return -1;
	}
	return 1;
}

static void replication_notify_now(struct mail_user *user)
{
	struct replication_user *ruser = REPLICATION_USER_CONTEXT(user);
	int ret;

	i_assert(ruser != NULL);
	i_assert(ruser->priority != REPLICATION_PRIORITY_NONE);
	i_assert(ruser->priority != REPLICATION_PRIORITY_SYNC);

	if ((ret = replication_fifo_notify(user, ruser->priority)) < 0 &&
	    !fifo_failed) {
		/* retry once, in case replication server was restarted */
		ret = replication_fifo_notify(user, ruser->priority);
	}
	if (ret != 0) {
		timeout_remove(&ruser->to);
		ruser->priority = REPLICATION_PRIORITY_NONE;
	}
}

static int replication_notify_sync(struct mail_user *user)
{
	struct replication_user *ruser = REPLICATION_USER_CONTEXT(user);
	string_t *str;
	char buf[1024];
	int fd;
	ssize_t ret;
	bool success = FALSE;

	i_assert(ruser != NULL);

	fd = net_connect_unix(ruser->socket_path);
	if (fd == -1) {
		i_error("net_connect_unix(%s) failed: %m", ruser->socket_path);
		return -1;
	}
	net_set_nonblock(fd, FALSE);

	/* <username> \t "sync" */
	str = t_str_new(256);
	str_append_tabescaped(str, user->username);
	str_append(str, "\tsync\n");
	alarm(ruser->sync_secs);
	if (write_full(fd, str_data(str), str_len(str)) < 0) {
		i_error("write(%s) failed: %m", ruser->socket_path);
	} else {
		/* + | - */
		ret = read(fd, buf, sizeof(buf));
		if (ret < 0) {
			if (errno != EINTR) {
				i_error("read(%s) failed: %m",
					ruser->socket_path);
			} else {
				i_warning("replication(%s): Sync failure: "
					  "Timeout in %u secs",
					  user->username, ruser->sync_secs);
			}
		} else if (ret == 0) {
			i_error("read(%s) failed: EOF", ruser->socket_path);
		} else if (buf[0] == '+') {
			/* success */
			success = TRUE;
		} else if (buf[0] == '-') {
			/* failure */
			if (buf[ret-1] == '\n') ret--;
			i_warning("replication(%s): Sync failure: %s",
				  user->username, t_strndup(buf+1, ret-1));
			i_warning("replication(%s): "
				  "Remote sent invalid input: %s",
				  user->username, t_strndup(buf, ret));
		}
	}
	alarm(0);
	if (close(fd) < 0)
		i_error("close(%s) failed: %m", ruser->socket_path);
	return success ? 0 : -1;
}

static void replication_notify(struct mail_namespace *ns,
			       enum replication_priority priority,
			       const char *event)
{
	struct replication_user *ruser;

	ruser = REPLICATION_USER_CONTEXT(ns->user);
	if (ruser == NULL)
		return;

	e_debug(ns->user->event,
		"replication: Replication requested by '%s', priority=%d",
		event, priority);

	if (priority == REPLICATION_PRIORITY_SYNC) {
		if (replication_notify_sync(ns->user) == 0) {
			timeout_remove(&ruser->to);
			ruser->priority = REPLICATION_PRIORITY_NONE;
			return;
		}
		/* sync replication failed, try as "high" via fifo */
		priority = REPLICATION_PRIORITY_HIGH;
	}

	if (ruser->priority < priority)
		ruser->priority = priority;
	if (ruser->to == NULL) {
		ruser->to = timeout_add_short(REPLICATION_NOTIFY_DELAY_MSECS,
					      replication_notify_now, ns->user);
	}
}

static void *
replication_mail_transaction_begin(struct mailbox_transaction_context *t)
{
	struct replication_mail_txn_context *ctx;

	ctx = i_new(struct replication_mail_txn_context, 1);
	ctx->ns = mailbox_get_namespace(t->box);
	ctx->reason = i_strdup(t->reason);
	if ((t->flags & MAILBOX_TRANSACTION_FLAG_SYNC) != 0) {
		/* Transaction is from dsync. Don't trigger replication back. */
		ctx->sync_trans = TRUE;
	}
	return ctx;
}

static void replication_mail_save(void *txn, struct mail *mail ATTR_UNUSED)
{
	struct replication_mail_txn_context *ctx =
		(struct replication_mail_txn_context *)txn;

	ctx->new_messages = TRUE;
}

static void replication_mail_copy(void *txn, struct mail *src,
				  struct mail *dst)
{
	struct replication_mail_txn_context *ctx =
		(struct replication_mail_txn_context *)txn;

	if (src->box->storage != dst->box->storage) {
		/* copy between storages, e.g. new mail delivery */
		ctx->new_messages = TRUE;
	} else {
		/* copy within storage, which isn't as high priority since the
		   mail already exists. and especially copies to Trash or to
		   lazy-expunge namespace is pretty low priority. */
	}
}

static bool
replication_want_sync_changes(const struct mail_transaction_commit_changes *changes)
{
	/* Replication needs to be triggered on all the user-visible changes,
	   but not e.g. due to writes to cache file. */
	return (changes->changes_mask &
		~MAIL_INDEX_TRANSACTION_CHANGE_OTHERS) != 0;
}

static void
replication_mail_transaction_commit(void *txn,
				    struct mail_transaction_commit_changes *changes)
{
	struct replication_mail_txn_context *ctx =
		(struct replication_mail_txn_context *)txn;
	struct replication_user *ruser =
		REPLICATION_USER_CONTEXT(ctx->ns->user);
	enum replication_priority priority;

	if (ruser != NULL && !ctx->sync_trans &&
	    (ctx->new_messages || replication_want_sync_changes(changes))) {
		priority = !ctx->new_messages ? REPLICATION_PRIORITY_LOW :
			ruser->sync_secs == 0 ? REPLICATION_PRIORITY_HIGH :
			REPLICATION_PRIORITY_SYNC;
		replication_notify(ctx->ns, priority, ctx->reason);
	}
	i_free(ctx->reason);
	i_free(ctx);
}

static void replication_mailbox_create(struct mailbox *box)
{
	replication_notify(mailbox_get_namespace(box),
			   REPLICATION_PRIORITY_LOW, "mailbox create");
}

static void
replication_mailbox_delete_commit(void *txn ATTR_UNUSED,
				  struct mailbox *box)
{
	replication_notify(mailbox_get_namespace(box),
			   REPLICATION_PRIORITY_LOW, "mailbox delete");
}

static void
replication_mailbox_rename(struct mailbox *src ATTR_UNUSED,
			   struct mailbox *dest)
{
	replication_notify(mailbox_get_namespace(dest),
			   REPLICATION_PRIORITY_LOW, "mailbox rename");
}

static void replication_mailbox_set_subscribed(struct mailbox *box,
					       bool subscribed ATTR_UNUSED)
{
	replication_notify(mailbox_get_namespace(box),
			   REPLICATION_PRIORITY_LOW, "mailbox subscribe");
}

static void replication_user_deinit(struct mail_user *user)
{
	struct replication_user *ruser = REPLICATION_USER_CONTEXT(user);

	i_assert(ruser != NULL);

	if (ruser->to != NULL) {
		replication_notify_now(user);
		if (ruser->to != NULL) {
			i_warning("%s: Couldn't send final notification "
				  "due to fifo being busy", fifo_path);
			timeout_remove(&ruser->to);
		}
	}

	ruser->module_ctx.super.deinit(user);
}

static void replication_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct replication_user *ruser;
	const char *value;

	value = mail_user_plugin_getenv(user, "mail_replica");
	if (value == NULL || value[0] == '\0') {
		e_debug(user->event, "replication: No mail_replica setting - replication disabled");
		return;
	}

	if (user->dsyncing) {
		/* we're running dsync, which means that the remote is telling
		   us about a change. don't trigger a replication back to it */
		e_debug(user->event, "replication: We're running dsync - replication disabled");
		return;
	}

	ruser = p_new(user->pool, struct replication_user, 1);
	ruser->module_ctx.super = *v;
	user->vlast = &ruser->module_ctx.super;
	v->deinit = replication_user_deinit;
	MODULE_CONTEXT_SET(user, replication_user_module, ruser);

	if (fifo_path == NULL) {
		/* we'll assume that all users have the same base_dir.
		   they really should. */
		fifo_path = i_strconcat(user->set->base_dir,
					"/"REPLICATION_FIFO_NAME, NULL);
	}
	ruser->socket_path = p_strconcat(user->pool, user->set->base_dir,
					 "/"REPLICATION_SOCKET_NAME, NULL);
	value = mail_user_plugin_getenv(user, "replication_sync_timeout");
	if (value != NULL && str_to_uint(value, &ruser->sync_secs) < 0) {
		i_error("replication(%s): "
			"Invalid replication_sync_timeout value: %s",
			user->username, value);
	}
}

static const struct notify_vfuncs replication_vfuncs = {
	.mail_transaction_begin = replication_mail_transaction_begin,
	.mail_save = replication_mail_save,
	.mail_copy = replication_mail_copy,
	.mail_transaction_commit = replication_mail_transaction_commit,
	.mailbox_create = replication_mailbox_create,
	.mailbox_delete_commit = replication_mailbox_delete_commit,
	.mailbox_rename = replication_mailbox_rename,
	.mailbox_set_subscribed = replication_mailbox_set_subscribed
};

static struct notify_context *replication_ctx;

static struct mail_storage_hooks replication_mail_storage_hooks = {
	.mail_user_created = replication_user_created
};

void replication_plugin_init(struct module *module)
{
	fifo_fd = -1;
	replication_ctx = notify_register(&replication_vfuncs);
	mail_storage_hooks_add(module, &replication_mail_storage_hooks);
}

void replication_plugin_deinit(void)
{
	i_close_fd_path(&fifo_fd, fifo_path);
	i_free_and_null(fifo_path);

	mail_storage_hooks_remove(&replication_mail_storage_hooks);
	notify_unregister(replication_ctx);
}

const char *replication_plugin_dependencies[] = { "notify", NULL };
