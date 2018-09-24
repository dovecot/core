/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "dlua-script.h"
#include "dlua-script-private.h"

#include "mail-storage.h"
#include "mail-user.h"
#include "mail-lua-plugin.h"
#include "mail-storage-lua.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-event-message-common.h"
#include "push-notification-txn-mbox.h"
#include "push-notification-txn-msg.h"

#include "push-notification-event-flagsclear.h"
#include "push-notification-event-flagsset.h"
#include "push-notification-event-mailboxcreate.h"
#include "push-notification-event-mailboxdelete.h"
#include "push-notification-event-mailboxrename.h"
#include "push-notification-event-mailboxsubscribe.h"
#include "push-notification-event-mailboxunsubscribe.h"
#include "push-notification-event-messageappend.h"
#include "push-notification-event-message-common.h"
#include "push-notification-event-messageexpunge.h"
#include "push-notification-event-messagenew.h"
#include "push-notification-event-messageread.h"
#include "push-notification-event-messagetrash.h"

#define DLUA_LOG_LABEL "push-notification-lua: "
#define DLUA_LOG_USERENV_KEY "push_notification_lua_script_file"

#define DLUA_FN_BEGIN_TXN "dovecot_lua_notify_begin_txn"
#define DLUA_FN_EVENT_PREFIX "dovecot_lua_notify_event"
#define DLUA_FN_END_TXN "dovecot_lua_notify_end_txn"

struct dlua_push_notification_context {
	struct dlua_script *script;
	bool debug;
};

struct dlua_push_notification_txn_context {
	int tx_ref;
};

#define DLUA_DEFAULT_EVENTS (\
	PUSH_NOTIFICATION_MESSAGE_HDR_FROM | PUSH_NOTIFICATION_MESSAGE_HDR_TO | \
	PUSH_NOTIFICATION_MESSAGE_HDR_SUBJECT | PUSH_NOTIFICATION_MESSAGE_HDR_DATE | \
	PUSH_NOTIFICATION_MESSAGE_BODY_SNIPPET)

static int
push_notification_driver_lua_init(struct push_notification_driver_config *config,
				  struct mail_user *user,
				  pool_t pool,
				  void **context,
				  const char **error_r)
{
	struct dlua_push_notification_context *ctx;
	const char *tmp, *file;

	if ((tmp = mail_user_plugin_getenv(user, DLUA_LOG_USERENV_KEY)) == NULL)
		tmp = hash_table_lookup(config->config, (const char *)"file");

	if (tmp == NULL) {
		struct dlua_script *script;
		/* if there is a script loaded, use the same context */
		if (mail_lua_plugin_get_script(user, &script)) {
			dlua_script_ref(script);
			ctx = p_new(pool, struct dlua_push_notification_context, 1);
			ctx->script = script;
			*context = ctx;
			return 0;
		}

		*error_r = "No file in config and no " DLUA_LOG_USERENV_KEY " set";
		return -1;
	}
	file = tmp;

	ctx = p_new(pool, struct dlua_push_notification_context, 1);

	push_notification_driver_debug(DLUA_LOG_LABEL, user, "Loading %s", file);

	if (dlua_script_create_file(file, &ctx->script, error_r) < 0) {
		/* there is a T_POP after this, which will break errors */
		*error_r = p_strdup(pool, *error_r);
		return -1;
	}

	/* register dovecot helpers */
	dlua_dovecot_register(ctx->script);
	dlua_register_mail_storage(ctx->script);

	push_notification_driver_debug(DLUA_LOG_LABEL, user, "Calling script_init");

	/* initialize script */
	if (dlua_script_init(ctx->script, error_r) < 0) {
		*error_r = p_strdup(pool, *error_r);
		dlua_script_unref(&ctx->script);
		return -1;
	}

	*context = ctx;
	return 0;
}

static bool push_notification_driver_lua_begin_txn
(struct push_notification_driver_txn *dtxn)
{
	struct mail_user *user = dtxn->ptxn->muser;
	struct dlua_push_notification_context *ctx = dtxn->duser->context;
	struct push_notification_event_messagenew_config *config1;
	struct push_notification_event_messageappend_config *config2;

	int luaerr;

	mail_user_ref(user);

	config1 = p_new(dtxn->ptxn->pool,
		       struct push_notification_event_messagenew_config, 1);
	config1->flags = DLUA_DEFAULT_EVENTS;
	push_notification_event_init(dtxn, "MessageNew", config1);
	push_notification_driver_debug(DLUA_LOG_LABEL, user,
				   "Handling MessageNew event");

	config2 = p_new(dtxn->ptxn->pool,
		       struct push_notification_event_messageappend_config, 1);
	config2->flags = DLUA_DEFAULT_EVENTS;
	push_notification_event_init(dtxn, "MessageAppend", config2);
	push_notification_driver_debug(DLUA_LOG_LABEL, user,
				   "Handling MessageAppend event");
	/* start txn and store whatever LUA gives us back, it's our txid */
	lua_getglobal(ctx->script->L, DLUA_FN_BEGIN_TXN);
	if (!lua_isfunction(ctx->script->L, -1)) {
		i_error("push_notification_lua: "
			"Missing function " DLUA_FN_BEGIN_TXN);
		return FALSE;
	}

	push_notification_driver_debug(DLUA_LOG_LABEL, user, "Calling "
				       DLUA_FN_BEGIN_TXN "(%s)", user->username);

	/* push username as argument */
	dlua_push_mail_user(ctx->script, user);
	if ((luaerr = lua_pcall(ctx->script->L, 1, 1, 0)) != 0) {
		i_error("push_notification_lua: %s",
			lua_tostring(ctx->script->L, -1));
		lua_pop(ctx->script->L, 1);
		return FALSE;
	}

	/* store the result */
	struct dlua_push_notification_txn_context *tctx =
		p_new(dtxn->ptxn->pool, struct dlua_push_notification_txn_context, 1);

	tctx->tx_ref = luaL_ref(ctx->script->L, LUA_REGISTRYINDEX);
	dtxn->context = tctx;

	return TRUE;
}

/* this function only works here, it converts MessageType to event_message_type */
static const char *push_notification_driver_lua_to_fn(const char *evname)
{
	/* camelcase to event_event_name (most events have two underscores) */
	string_t *fn = t_str_new(strlen(evname)+strlen(DLUA_FN_EVENT_PREFIX)+2);
	str_append(fn, DLUA_FN_EVENT_PREFIX);

	for(;*evname != '\0'; evname++) {
		if (*evname >= 'A' && *evname <= 'Z') {
			str_append_c(fn, '_');
			str_append_c(fn, (*evname) - 'A' + 'a');
		} else {
			str_append_c(fn, *evname);
		}
	}

	return str_c(fn);
}

static void
push_notification_lua_push_flagsclear(const struct push_notification_txn_event *event,
				      struct dlua_script *script)
{
	/* push cleared flags */
	unsigned int size;
	struct push_notification_event_flagsclear_data *data = event->data;

	if (array_is_created(&data->keywords_clear)) {
		size = array_count(&data->keywords_clear);
		lua_createtable(script->L, size, 0);
		for(unsigned int i=0; i<size; i++) {
			const char *const *kw =
				array_idx(&data->keywords_clear, i);
			lua_pushstring(script->L, *kw);
			lua_rawseti(script->L, -2, i+1);
		}
		lua_setfield(script->L, -2, "keywords_clear");
	}

	if (array_is_created(&data->keywords_old)) {
		size = array_count(&data->keywords_old);
		lua_createtable(script->L, size, 0);
		for(unsigned int i=0; i<size; i++) {
			const char *const *kw =
				array_idx(&data->keywords_old, i);
			lua_pushstring(script->L, *kw);
			lua_rawseti(script->L, -2, i+1);
		}
		lua_setfield(script->L, -2, "keywords_old");
	}
}

static void
push_notification_lua_push_flagsset(const struct push_notification_txn_event *event,
				    struct dlua_script *script)
{
	/* push cleared flags */
	unsigned int size;
	struct push_notification_event_flagsset_data *data = event->data;

	lua_pushnumber(script->L, data->flags_set);
	lua_setfield(script->L, -2, "flags");

	if (array_is_created(&data->keywords_set)) {
		size = array_count(&data->keywords_set);
		lua_createtable(script->L, size, 0);
		for(unsigned int i=0; i<size; i++) {
			const char *const *kw =
				array_idx(&data->keywords_set, i);
			lua_pushstring(script->L, *kw);
			lua_rawseti(script->L, -2, i+1);
		}
		lua_setfield(script->L, -2, "keywords_set");
	}
}

static void
push_notification_lua_push_mailboxrename(const struct push_notification_txn_event *event,
					 struct dlua_script *script)
{
	struct push_notification_event_mailboxrename_data *data = event->data;

	lua_pushstring(script->L, data->old_mbox);
	lua_setfield(script->L, -2, "mailbox_old");
}

static void
push_notification_lua_push_messageappend(const struct push_notification_txn_event *event,
					 struct dlua_script *script)
{
	struct push_notification_event_messageappend_data *data = event->data;

	lua_pushstring(script->L, data->from);
	lua_setfield(script->L, -2, "from");

	lua_pushstring(script->L, data->to);
	lua_setfield(script->L, -2, "to");

	lua_pushstring(script->L, data->subject);
	lua_setfield(script->L, -2, "subject");

	lua_pushstring(script->L, data->snippet);
	lua_setfield(script->L, -2, "snippet");
}

static void
push_notification_lua_push_messagenew(const struct push_notification_txn_event *event,
				      struct dlua_script *script)
{
	struct push_notification_event_messagenew_data *data = event->data;

	lua_pushnumber(script->L, data->date);
	lua_setfield(script->L, -2, "date");

	lua_pushnumber(script->L, data->date_tz);
	lua_setfield(script->L, -2, "tz");

	lua_pushstring(script->L, data->from);
	lua_setfield(script->L, -2, "from");

	lua_pushstring(script->L, data->to);
	lua_setfield(script->L, -2, "to");

	lua_pushstring(script->L, data->subject);
	lua_setfield(script->L, -2, "subject");

	lua_pushstring(script->L, data->snippet);
	lua_setfield(script->L, -2, "snippet");
}

/* events that need special treatment */
static struct push_notification_event_to_lua {
	const char *event_name;
	void (*push)(const struct push_notification_txn_event *event,
		     struct dlua_script *script);
} event_to_push_table[] = {
	{
		.event_name = "FlagsClear",
		.push = push_notification_lua_push_flagsclear
	},
	{
		.event_name = "FlagsSet",
		.push = push_notification_lua_push_flagsset
	},
	{
		.event_name = "MailboxRename",
		.push = push_notification_lua_push_mailboxrename
	},
	{
		.event_name = "MessageAppend",
		.push = push_notification_lua_push_messageappend
	},
	{
		.event_name = "MessageNew",
		.push = push_notification_lua_push_messagenew
	},
};

static void
push_notification_driver_lua_pushevent(const struct push_notification_txn_event *event,
				       struct dlua_push_notification_context *ctx)
{
	struct dlua_script *script = ctx->script;
	const char *name = event->event->event->name;

	/* create a table */
	lua_newtable(script->L);

	/* event name */
	lua_pushstring(script->L, name);
	lua_setfield(script->L, -2, "name");

	for(size_t i = 0; i < N_ELEMENTS(event_to_push_table); i++)
		if (strcmp(event_to_push_table[i].event_name, name) == 0)
			event_to_push_table[i].push(event, script);
}

static void
push_notification_driver_lua_call(struct dlua_push_notification_context *ctx,
				  struct dlua_push_notification_txn_context *tctx,
				  struct mail_user *user,
				  const struct push_notification_txn_event *event,
				  const struct push_notification_txn_mbox *mbox,
				  struct push_notification_txn_msg *msg)
{
	int luaerr;
	const char *fn =
		push_notification_driver_lua_to_fn(event->event->event->name);

	push_notification_driver_debug(DLUA_LOG_LABEL, user, "Looking up %s", fn);

	lua_getglobal(ctx->script->L, fn);
	if (!lua_isfunction(ctx->script->L, -1)) {
		push_notification_driver_debug(DLUA_LOG_LABEL, user, "Cannot find function %s",
					       fn);
		return;
	}

	/* push context */
	lua_rawgeti(ctx->script->L, LUA_REGISTRYINDEX, tctx->tx_ref);

	/* push event + common fields */
	if (mbox != NULL) {
		push_notification_driver_lua_pushevent(event, ctx);
		lua_pushstring(ctx->script->L, mbox->mailbox);
		lua_setfield(ctx->script->L, -2, "mailbox");
		push_notification_driver_debug(DLUA_LOG_LABEL, user,
					       "Calling %s(ctx, event[name=%s,mailbox=%s])",
					       fn, event->event->event->name,
					       mbox->mailbox);
	} else if (msg != NULL) {
		push_notification_driver_lua_pushevent(event, ctx);
		lua_pushstring(ctx->script->L, msg->mailbox);
		lua_setfield(ctx->script->L, -2, "mailbox");
		lua_pushnumber(ctx->script->L, msg->uid);
		lua_setfield(ctx->script->L, -2, "uid");
		lua_pushnumber(ctx->script->L, msg->uid_validity);
		lua_setfield(ctx->script->L, -2, "uid_validity");
		push_notification_driver_debug(DLUA_LOG_LABEL, user,
					       "Calling %s(ctx, event[name=%s,mailbox=%s,uid=%u])",
					       fn, event->event->event->name,
					       msg->mailbox, msg->uid);
	} else
		i_unreached();

	/* finally push user too, makes everything easier */
	dlua_push_mail_user(ctx->script, user);

	/* perform call */
	if ((luaerr = lua_pcall(ctx->script->L, 3, 0, 0)) != 0) {
		i_error("push_notification_lua: %s",
			lua_tostring(ctx->script->L, -1));
		lua_pop(ctx->script->L, 1);
	}
}

static void
push_notification_driver_lua_process_mbox(struct push_notification_driver_txn *dtxn,
					  struct push_notification_txn_mbox *mbox)
{
	struct push_notification_txn_event *const *event;
	struct dlua_push_notification_context *ctx = dtxn->duser->context;
	struct dlua_push_notification_txn_context *tctx = dtxn->context;
	struct mail_user *user = dtxn->ptxn->muser;

	if (array_is_created(&mbox->eventdata)) {
		array_foreach(&mbox->eventdata, event) {
			push_notification_driver_lua_call(ctx, tctx, user,
							  (*event), mbox, NULL);
		}
	}
}

static void
push_notification_driver_lua_process_msg(struct push_notification_driver_txn *dtxn,
					 struct push_notification_txn_msg *msg)
{
	struct push_notification_txn_event *const *event;
	struct dlua_push_notification_context *ctx = dtxn->duser->context;
	struct dlua_push_notification_txn_context *tctx = dtxn->context;
	struct mail_user *user = dtxn->ptxn->muser;

	if (array_is_created(&msg->eventdata)) {
		array_foreach(&msg->eventdata, event) {
			push_notification_driver_lua_call(ctx, tctx, user,
							  (*event), NULL, msg);
		}
	}
}

static void
push_notification_driver_lua_end_txn(struct push_notification_driver_txn *dtxn,
				     bool success)
{
	/* call end txn */
	struct dlua_push_notification_context *ctx = dtxn->duser->context;
	struct dlua_push_notification_txn_context *tctx = dtxn->context;
	struct mail_user *user = dtxn->ptxn->muser;

	lua_getglobal(ctx->script->L, DLUA_FN_END_TXN);
	if (!lua_isfunction(ctx->script->L, -1)) {
		i_error("push_notification_lua: "
			"Missing function " DLUA_FN_END_TXN);
	} else {
		push_notification_driver_debug(DLUA_LOG_LABEL, user,
					       "Calling " DLUA_FN_END_TXN);
		lua_rawgeti(ctx->script->L, LUA_REGISTRYINDEX, tctx->tx_ref);
		lua_pushboolean(ctx->script->L, success);
		if (lua_pcall(ctx->script->L, 2, 0, 0) != 0) {
			i_error("push_notification_lua: %s",
				lua_tostring(ctx->script->L, -1));
			lua_pop(ctx->script->L, 1);
		}
	}

	/* release context */
	luaL_unref(ctx->script->L, LUA_REGISTRYINDEX, tctx->tx_ref);

	mail_user_unref(&user);
}

static void
push_notification_driver_lua_deinit(struct push_notification_driver_user *duser)
{
	/* call lua deinit */
	struct dlua_push_notification_context *ctx = duser->context;
	dlua_script_unref(&ctx->script);
}

static void push_notification_driver_lua_cleanup(void)
{
	/* noop */
}

/* Driver definition */

struct push_notification_driver push_notification_driver_lua = {
	.name = "lua",
	.v = {
		.init = push_notification_driver_lua_init,
		.begin_txn = push_notification_driver_lua_begin_txn,
		.process_mbox = push_notification_driver_lua_process_mbox,
		.process_msg = push_notification_driver_lua_process_msg,
		.end_txn = push_notification_driver_lua_end_txn,
		.deinit = push_notification_driver_lua_deinit,
		.cleanup = push_notification_driver_lua_cleanup
	}
};

void push_notification_lua_plugin_init(struct module *module);
void push_notification_lua_plugin_deinit(void);

void push_notification_lua_plugin_init(struct module *module ATTR_UNUSED)
{
	push_notification_driver_register(&push_notification_driver_lua);
}

void push_notification_lua_plugin_deinit(void)
{
	push_notification_driver_unregister(&push_notification_driver_lua);
}

const char *push_notification_lua_plugin_version = DOVECOT_ABI_VERSION;
const char *push_notification_lua_plugin_dependencies[] =
	{ "push_notification", "mail_lua", NULL};
