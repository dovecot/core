/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "strescape.h"
#include "eacces-error.h"
#include "write-full.h"
#include "module-context.h"
#include "mail-storage-private.h"

#define WELCOME_SOCKET_TIMEOUT_SECS 30

#define WELCOME_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, welcome_storage_module)

struct welcome_mailbox {
	union mailbox_module_context module_ctx;
	bool created;
};

static MODULE_CONTEXT_DEFINE_INIT(welcome_storage_module,
				  &mail_storage_module_register);

static void script_execute(struct mail_user *user, const char *cmd, bool wait)
{
	const char *socket_path, *const *args;
	string_t *str;
	char buf[1024];
	int fd, ret;

	e_debug(user->event, "welcome: Executing %s (wait=%d)", cmd, wait ? 1 : 0);

	args = t_strsplit_spaces(cmd, " ");
	socket_path = args[0];
	args++;

	if (*socket_path != '/') {
		socket_path = t_strconcat(user->set->base_dir, "/",
					  socket_path, NULL);
	}
	if ((fd = net_connect_unix_with_retries(socket_path, 1000)) < 0) {
		if (errno == EACCES) {
			i_error("welcome: %s",
				eacces_error_get("net_connect_unix",
						 socket_path));
		} else {
			i_error("welcome: net_connect_unix(%s) failed: %m",
				socket_path);
		}
		return;
	}

	str = t_str_new(1024);
	str_append(str, "VERSION\tscript\t4\t0\n");
	if (!wait)
		str_append(str, "noreply\n");
	else
		str_append(str, "-\n");
	for (; *args != NULL; args++) {
		str_append_tabescaped(str, *args);
		str_append_c(str, '\n');
	}
	str_append_c(str, '\n');

	alarm(WELCOME_SOCKET_TIMEOUT_SECS);
	net_set_nonblock(fd, FALSE);
	if (write_full(fd, str_data(str), str_len(str)) < 0)
		i_error("write(%s) failed: %m", socket_path);
	else if (wait) {
		ret = read(fd, buf, sizeof(buf));
		if (ret < 0)
			i_error("welcome: read(%s) failed: %m", socket_path);
		else if (ret < 2)
			i_error("welcome: %s failed: Only %d bytes read", socket_path, ret);
		else if (buf[0] != '+')
			i_error("welcome: %s failed: Script returned error", socket_path);
	}
	if (close(fd) < 0)
		i_error("close(%s) failed: %m", socket_path);
}

static int
welcome_create_box(struct mailbox *box,
		   const struct mailbox_update *update, bool directory)
{
	struct welcome_mailbox *wbox = WELCOME_CONTEXT(box);

	if (wbox->module_ctx.super.create_box(box, update, directory) < 0)
		return -1;
	/* the mailbox isn't fully created here yet, so just mark it as created
	   and wait until open() time to actually run it */
	wbox->created = TRUE;
	return 0;
}

static int welcome_open_box(struct mailbox *box)
{
	struct welcome_mailbox *wbox = WELCOME_CONTEXT(box);
	const char *cmd;

	cmd = !wbox->created ? NULL :
		mail_user_plugin_getenv(box->storage->user, "welcome_script");
	if (cmd != NULL) {
		bool wait = mail_user_plugin_getenv_bool(box->storage->user,
							 "welcome_wait");
		script_execute(box->storage->user, cmd, wait);
	}
	return wbox->module_ctx.super.open(box);
}

static void welcome_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct welcome_mailbox *wbox;

	if (!box->inbox_user)
		return;

	wbox = p_new(box->pool, struct welcome_mailbox, 1);
	wbox->module_ctx.super = *v;
	box->vlast = &wbox->module_ctx.super;

	v->create_box = welcome_create_box;
	v->open = welcome_open_box;
	MODULE_CONTEXT_SET(box, welcome_storage_module, wbox);
}

static struct mail_storage_hooks welcome_mail_storage_hooks = {
	.mailbox_allocated = welcome_mailbox_allocated
};

void welcome_plugin_init(struct module *module);
void welcome_plugin_deinit(void);

void welcome_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &welcome_mail_storage_hooks);
}

void welcome_plugin_deinit(void)
{
	mail_storage_hooks_remove(&welcome_mail_storage_hooks);
}

const char *welcome_plugin_version = DOVECOT_ABI_VERSION;
