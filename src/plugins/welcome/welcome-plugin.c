/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "ioloop.h"
#include "llist.h"
#include "str.h"
#include "program-client.h"
#include "program-client-private.h"
#include "strescape.h"
#include "eacces-error.h"
#include "write-full.h"
#include "module-context.h"
#include "settings.h"
#include "settings-parser.h"
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

struct welcome_settings {
	pool_t pool;
	bool welcome_wait;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct welcome_settings)
static const struct setting_define welcome_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "welcome",
	  .required_setting = "execute", },
	DEF(BOOL, welcome_wait),

	SETTING_DEFINE_LIST_END
};
static const struct welcome_settings welcome_default_settings = {
	.welcome_wait = FALSE,
};
const struct setting_parser_info welcome_setting_parser_info = {
	.name = "welcome",
	.plugin_dependency = "lib99_welcome_plugin",
	.defines = welcome_setting_defines,
	.defaults = &welcome_default_settings,
	.struct_size = sizeof(struct welcome_settings),
	.pool_offset1 = 1 + offsetof(struct welcome_settings, pool),
};

static MODULE_CONTEXT_DEFINE_INIT(welcome_storage_module,
				  &mail_storage_module_register);

static void welcome_client_destroy(struct welcome_client_list **_wclient) {
	struct welcome_client_list *wclient = *_wclient;

	*_wclient = NULL;

	program_client_destroy(&wclient->client);
	i_free(wclient);
}

static void script_finish(enum program_client_exit_status ret,
			  struct program_client *client)
{
	if (ret != PROGRAM_CLIENT_EXIT_STATUS_SUCCESS)
		e_error(client->event, "Execution failed: %d", ret);
}

static int script_execute(struct event *event, bool wait, const char **error_r)
{
	struct program_client_parameters params = {
		.client_connect_timeout_msecs = 1000,
		.no_reply = !wait,
	};

	struct welcome_client_list *wclient = i_new(struct welcome_client_list, 1);
	int ret = program_client_create_auto(event, &params,
					     &wclient->client, error_r);
	if (ret <= 0) {
		/* if execute { .. } is missing, assume it's intentional and
		   don't log an error. */
		return ret;
	}

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
	return 0;
}

static int
welcome_create_box(struct mailbox *box,
		   const struct mailbox_update *update, bool directory)
{
	struct welcome_mailbox *wbox = WELCOME_CONTEXT(box);

	if (wbox->module_ctx.super.create_box(box, update, directory) < 0)
		return -1;

	const struct welcome_settings *set = NULL;
	const char *error;
	struct event *event = event_create(box->storage->user->event);
	settings_event_add_filter_name(event, "welcome");
	event_set_append_log_prefix(event, "welcome: ");
	if (settings_get(event, &welcome_setting_parser_info, 0,
			 &set, &error) < 0 ||
	    script_execute(event, set->welcome_wait, &error) < 0) {
		e_error(event, "%s", error);
		/* the mailbox was already created, so return success */
	}
	settings_free(set);
	event_unref(&event);
	return 0;
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
