/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "ioloop.h"
#include "llist.h"
#include "str.h"
#include "program-client.h"
#include "strescape.h"
#include "eacces-error.h"
#include "write-full.h"
#include "module-context.h"
#include "mail-storage-private.h"

#define WELCOME_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, welcome_storage_module)

struct welcome_mailbox {
	union mailbox_module_context module_ctx;
	bool created;
};

static struct welcome_client_list {
	struct welcome_client_list *prev, *next;
	struct program_client *client;
} *welcome_clients = NULL;

static MODULE_CONTEXT_DEFINE_INIT(welcome_storage_module,
				  &mail_storage_module_register);

static void welcome_client_destroy(struct welcome_client_list **_wclient) {
	struct welcome_client_list *wclient = *_wclient;

	*_wclient = NULL;

	program_client_destroy(&wclient->client);
	i_free(wclient);
}

static void script_finish(enum program_client_exit_status ret,
			  struct program_client *client ATTR_UNUSED)
{
	if (ret != PROGRAM_CLIENT_EXIT_STATUS_SUCCESS)
		i_error("welcome: Execution failed: %d", ret);
}

static void script_execute(struct mail_user *user, const char *cmd, bool wait)
{
	const char *socket_path, *home, *const *args;

	if (mail_user_get_home(user, &home) < 0)
		home = NULL;

	struct program_client_settings set = {
		.client_connect_timeout_msecs = 1000,
		.event = user->event,
		.debug = user->mail_debug,
		.home = home,
	};

	e_debug(user->event, "welcome: Executing %s (wait=%d)", cmd, wait ? 1 : 0);

	args = t_strsplit_spaces(cmd, " ");
	socket_path = args[0];
	args++;

	if (*socket_path != '/') {
		socket_path = t_strconcat(user->set->base_dir, "/",
					  socket_path, NULL);
	}

	struct welcome_client_list *wclient = i_new(struct welcome_client_list, 1);
	wclient->client = program_client_unix_create(socket_path, args, &set, !wait);

	if (wait) {
		enum program_client_exit_status ret =
			program_client_run(wclient->client);
		script_finish(ret, wclient->client);
		welcome_client_destroy(&wclient);
	} else {
		DLLIST_PREPEND(&welcome_clients, wclient);
		program_client_run_async(wclient->client, script_finish,
					 wclient->client);
	}
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
	while (welcome_clients != NULL) {
		struct welcome_client_list *next = welcome_clients->next;

		program_client_wait(welcome_clients->client);
		welcome_client_destroy(&welcome_clients);
		welcome_clients = next;
	}

	mail_storage_hooks_remove(&welcome_mail_storage_hooks);
}

const char *welcome_plugin_version = DOVECOT_ABI_VERSION;
