/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "hash.h"
#include "dlua-script.h"
#include "dlua-script-private.h"

#include "mail-storage.h"
#include "mail-user.h"
#include "mail-lua-plugin.h"
#include "mail-storage-lua.h"

#include "push-notification-plugin.h"
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

#define DLUA_LOG_USERENV_KEY "push_notification_lua_script_file"

#define DLUA_FN_BEGIN_TXN "dovecot_lua_notify_begin_txn"
#define DLUA_FN_EVENT_PREFIX "dovecot_lua_notify_event"
#define DLUA_FN_END_TXN "dovecot_lua_notify_end_txn"

#define DLUA_CALL_FINISHED "push_notification_lua_call_finished"

struct dlua_push_notification_context {
	struct dlua_script *script;
	struct event *event;
	bool debug;

	struct push_notification_event_messagenew_config config_mn;
	struct push_notification_event_messageappend_config config_ma;
	struct push_notification_event_flagsclear_config config_fc;
	struct push_notification_event_flagsset_config config_fs;
};

struct dlua_push_notification_txn_context {
	int tx_ref;
};

#define DLUA_DEFAULT_EVENTS (\
	PUSH_NOTIFICATION_MESSAGE_HDR_FROM | PUSH_NOTIFICATION_MESSAGE_HDR_TO | \
	PUSH_NOTIFICATION_MESSAGE_HDR_SUBJECT | PUSH_NOTIFICATION_MESSAGE_HDR_DATE | \
	PUSH_NOTIFICATION_MESSAGE_BODY_SNIPPET)

static const char *push_notification_driver_lua_to_fn(const char *evname);

static int
push_notification_driver_lua_init(struct push_notification_driver_config *config,
				  struct mail_user *user,
				  pool_t pool,
				  void **context,
				  const char **error_r)
{
	struct dlua_push_notification_context *ctx;
	const char *tmp, *file;
	struct event *event = event_create(user->event);
	event_add_category(event, &event_category_push_notification);
	event_set_append_log_prefix(event, "lua: ");

	if ((tmp = mail_user_plugin_getenv(user, DLUA_LOG_USERENV_KEY)) == NULL)
		tmp = hash_table_lookup(config->config, (const char *)"file");

	if (tmp == NULL) {
		struct dlua_script *script;
		/* if there is a script loaded, use the same context */
		if (mail_lua_plugin_get_script(user, &script)) {
			dlua_script_ref(script);
			ctx = p_new(pool, struct dlua_push_notification_context, 1);
			ctx->script = script;
			ctx->event = event;
			*context = ctx;
			return 0;
		}

		event_unref(&event);
		*error_r = "No file in config and no " DLUA_LOG_USERENV_KEY " set";
		return -1;
	}
	file = tmp;

	ctx = p_new(pool, struct dlua_push_notification_context, 1);
	ctx->event = event;

	e_debug(ctx->event, "Loading %s", file);

	if (dlua_script_create_file(file, &ctx->script, event, error_r) < 0) {
		/* there is a T_POP after this, which will break errors */
		event_unref(&event);
		*error_r = p_strdup(pool, *error_r);
		return -1;
	}

	/* register dovecot helpers */
	dlua_dovecot_register(ctx->script);
	dlua_register_mail_storage(ctx->script);

	e_debug(ctx->event, "Calling script_init");

	/* initialize script */
	if (dlua_script_init(ctx->script, error_r) < 0) {
		*error_r = p_strdup(pool, *error_r);
		event_unref(&event);
		dlua_script_unref(&ctx->script);
		return -1;
	}

	*context = ctx;
	return 0;
}

static bool
push_notification_driver_lua_init_events(struct push_notification_driver_txn *dtxn)
{
	struct dlua_push_notification_context *ctx = dtxn->duser->context;
	const struct push_notification_event *const *event;
	ctx->config_mn.flags = DLUA_DEFAULT_EVENTS;
	ctx->config_ma.flags = DLUA_DEFAULT_EVENTS;
	ctx->config_fc.store_old = TRUE;
	bool found_one = FALSE;

	/* register *all* events that are present in Lua */
	array_foreach(&push_notification_events, event) {
		const char *name = (*event)->name;
		const char *fn = push_notification_driver_lua_to_fn(name);
		if (!dlua_script_has_function(ctx->script, fn))
			continue;

		found_one = TRUE;

		e_debug(ctx->event, "Found %s, handling %s event", fn, name);

		if (strcmp(name, "MessageNew") == 0) {
			push_notification_event_init(dtxn, name, &ctx->config_mn);
		} else if (strcmp(name, "MessageAppend") == 0) {
			push_notification_event_init(dtxn, name, &ctx->config_ma);
		} else if (strcmp(name, "FlagsSet") == 0) {
			push_notification_event_init(dtxn, name, &ctx->config_fs);
		} else if (strcmp(name, "FlagsClear") == 0) {
			push_notification_event_init(dtxn, name, &ctx->config_fc);
		} else if ((*event)->init.default_config != NULL) {
			void *config = (*event)->init.default_config();
			push_notification_event_init(dtxn, name, config);
		} else {
			push_notification_event_init(dtxn, name, NULL);
		}
	}

	return found_one;
}

static bool push_notification_driver_lua_begin_txn
(struct push_notification_driver_txn *dtxn)
{
	struct mail_user *user = dtxn->ptxn->muser;
	struct dlua_push_notification_context *ctx = dtxn->duser->context;
        struct event *event = event_create(ctx->event);
        event_set_name(event, DLUA_CALL_FINISHED);
        event_add_str(event, "function_name", DLUA_FN_BEGIN_TXN);

	int luaerr;

	/* start txn and store whatever LUA gives us back, it's our txid */
	lua_getglobal(ctx->script->L, DLUA_FN_BEGIN_TXN);
	if (!lua_isfunction(ctx->script->L, -1)) {
		event_add_str(event, "error", "Missing function " DLUA_FN_BEGIN_TXN);
		e_error(event, "Missing function " DLUA_FN_BEGIN_TXN);
		event_unref(&event);
		return FALSE;
	}

	if (!push_notification_driver_lua_init_events(dtxn)) {
		e_debug(event, "No event handlers found in script");
		event_unref(&event);
		return FALSE;
	}

	e_debug(ctx->event, "Calling " DLUA_FN_BEGIN_TXN "(%s)", user->username);

	/* push mail user as argument */
	dlua_push_mail_user(ctx->script, user);
	if ((luaerr = lua_pcall(ctx->script->L, 1, 1, 0)) != 0) {
		const char *error = lua_tostring(ctx->script->L, -1);
		event_add_str(event, "error", error);
		e_error(event, "%s", error);
		lua_pop(ctx->script->L, 1);
		return FALSE;
	}

	e_debug(event, "Called " DLUA_FN_BEGIN_TXN);
	event_unref(&event);

	/* store the result */
	struct dlua_push_notification_txn_context *tctx =
		p_new(dtxn->ptxn->pool, struct dlua_push_notification_txn_context, 1);

	tctx->tx_ref = luaL_ref(ctx->script->L, LUA_REGISTRYINDEX);
	dtxn->context = tctx;
	mail_user_ref(user);

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

/* pushes lua list of flags */
static void dlua_pushflags(struct dlua_script *script, enum mail_flags flags)
{
	lua_newtable(script->L);
	int idx = 1;

	if ((flags & MAIL_ANSWERED) != 0) {
		lua_pushliteral(script->L, "\\Answered");
		lua_rawseti(script->L, -2, idx++);
	}
	if ((flags & MAIL_FLAGGED) != 0) {
		lua_pushliteral(script->L, "\\Flagged");
		lua_rawseti(script->L, -2, idx++);
	}
	if ((flags & MAIL_DELETED) != 0) {
		lua_pushliteral(script->L, "\\Deleted");
		lua_rawseti(script->L, -2, idx++);
	}
	if ((flags & MAIL_SEEN) != 0) {
		lua_pushliteral(script->L, "\\Seen");
		lua_rawseti(script->L, -2, idx++);
	}
	if ((flags & MAIL_DRAFT) != 0) {
		lua_pushliteral(script->L, "\\Draft");
		lua_rawseti(script->L, -2, idx++);
	}
	if ((flags & MAIL_RECENT) != 0) {
		lua_pushliteral(script->L, "\\Recent");
		lua_rawseti(script->L, -2, idx++);
	}
}

static void
dlua_pushkeywords(struct dlua_script *script, const char *const *keywords,
		  unsigned int count)
{
	lua_newtable(script->L);
	if (keywords == NULL)
		return;
	for (unsigned int idx = 0; idx < count; idx++) {
		lua_pushstring(script->L, keywords[idx]);
		lua_rawseti(script->L, -2, idx+1);
	}
}

static void
push_notification_lua_push_flagsclear(const struct push_notification_txn_event *event,
				      struct dlua_script *script)
{
	/* push cleared flags */
	unsigned int size = 0;
	struct push_notification_event_flagsclear_data *data = event->data;

	dlua_pushflags(script, data->flags_clear);
	lua_setfield(script->L, -2, "flags");
	dlua_pushflags(script, data->flags_old);
	lua_setfield(script->L, -2, "flags_old");

	if (array_is_created(&data->keywords_clear)) {
		const char *const *kw = array_get(&data->keywords_clear, &size);
		dlua_pushkeywords(script, kw, size);
		lua_setfield(script->L, -2, "keywords_clear");
	}

	if (array_is_created(&data->keywords_old)) {
		const char *const *kw = array_get(&data->keywords_old, &size);
		dlua_pushkeywords(script, kw, size);
		lua_setfield(script->L, -2, "keywords_old");
	}
}

static void
push_notification_lua_push_flagsset(const struct push_notification_txn_event *event,
				    struct dlua_script *script)
{
	/* push cleared flags */
	unsigned int size = 0;
	struct push_notification_event_flagsset_data *data = event->data;

	dlua_pushflags(script, data->flags_set);
	lua_setfield(script->L, -2, "flags");

	if (array_is_created(&data->keywords_set)) {
		const char *const *kw = array_get(&data->keywords_set, &size);
		dlua_pushkeywords(script, kw, size);
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
				  const struct push_notification_txn_event *event,
				  const struct push_notification_txn_mbox *mbox,
				  struct push_notification_txn_msg *msg)
{
	int luaerr;
	const char *fn =
		push_notification_driver_lua_to_fn(event->event->event->name);
	struct event *e = event_create(ctx->event);
	event_set_name(e, DLUA_CALL_FINISHED);
	event_add_str(e, "event_name", event->event->event->name);
	event_add_str(e, "function_name", fn);

	/* this has been assured already in init */
	lua_getglobal(ctx->script->L, fn);
	i_assert(lua_isfunction(ctx->script->L, -1));

	/* push context */
	lua_rawgeti(ctx->script->L, LUA_REGISTRYINDEX, tctx->tx_ref);

	/* push event + common fields */
	push_notification_driver_lua_pushevent(event, ctx);

	if (mbox != NULL) {
		lua_pushstring(ctx->script->L, mbox->mailbox);
		lua_setfield(ctx->script->L, -2, "mailbox");
		e_debug(ctx->event, "Calling %s(ctx, event[name=%s,mailbox=%s])",
				    fn, event->event->event->name,
				    mbox->mailbox);
		event_add_str(e, "mailbox", mbox->mailbox);
	} else if (msg != NULL) {
		lua_pushstring(ctx->script->L, msg->mailbox);
		lua_setfield(ctx->script->L, -2, "mailbox");
		lua_pushnumber(ctx->script->L, msg->uid);
		lua_setfield(ctx->script->L, -2, "uid");
		lua_pushnumber(ctx->script->L, msg->uid_validity);
		lua_setfield(ctx->script->L, -2, "uid_validity");
		e_debug(ctx->event, "Calling %s(ctx, event[name=%s,mailbox=%s,uid=%u])",
				    fn, event->event->event->name,
				    msg->mailbox, msg->uid);
		event_add_str(e, "mailbox", msg->mailbox);
		event_add_int(e, "uid", msg->uid);
	} else
		i_unreached();

	/* perform call */
	if ((luaerr = lua_pcall(ctx->script->L, 2, 0, 0)) != 0) {
		const char *error = lua_tostring(ctx->script->L, -1);
		event_add_str(e, "error", error);
		e_error(e, "%s", error);
		lua_pop(ctx->script->L, 1);
	} else {
		e_debug(e, "Called %s", fn);
	}
	event_unref(&e);
}

static void
push_notification_driver_lua_process_mbox(struct push_notification_driver_txn *dtxn,
					  struct push_notification_txn_mbox *mbox)
{
	struct push_notification_txn_event *const *event;
	struct dlua_push_notification_context *ctx = dtxn->duser->context;
	struct dlua_push_notification_txn_context *tctx = dtxn->context;

	if (array_is_created(&mbox->eventdata)) {
		array_foreach(&mbox->eventdata, event) {
			push_notification_driver_lua_call(ctx, tctx,
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

	if (array_is_created(&msg->eventdata)) {
		array_foreach(&msg->eventdata, event) {
			push_notification_driver_lua_call(ctx, tctx,
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
	struct event *event = event_create(ctx->event);
	event_set_name(event, DLUA_CALL_FINISHED);
	event_add_str(event, "function_name", DLUA_FN_END_TXN);

	lua_getglobal(ctx->script->L, DLUA_FN_END_TXN);
	if (!lua_isfunction(ctx->script->L, -1)) {
		e_error(event, "Missing function " DLUA_FN_END_TXN);
	} else {
		e_debug(ctx->event, "Calling " DLUA_FN_END_TXN);
		lua_rawgeti(ctx->script->L, LUA_REGISTRYINDEX, tctx->tx_ref);
		lua_pushboolean(ctx->script->L, success);
		if (lua_pcall(ctx->script->L, 2, 0, 0) != 0) {
			const char *error = lua_tostring(ctx->script->L, -1);
			event_add_str(event, "error", error);
			e_error(event, "%s", error);
			lua_pop(ctx->script->L, 1);
		} else {
			e_debug(event, "Called " DLUA_FN_END_TXN);
		}
	}

	event_unref(&event);
	/* release context */
	luaL_unref(ctx->script->L, LUA_REGISTRYINDEX, tctx->tx_ref);
	/* call gc here */
	(void)lua_gc(ctx->script->L, LUA_GCCOLLECT, 1);
	mail_user_unref(&user);
}

static void
push_notification_driver_lua_deinit(struct push_notification_driver_user *duser)
{
	/* call lua deinit */
	struct dlua_push_notification_context *ctx = duser->context;
	dlua_script_unref(&ctx->script);
	event_unref(&ctx->event);
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
