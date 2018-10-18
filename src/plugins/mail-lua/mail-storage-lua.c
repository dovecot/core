/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "var-expand.h"
#include "dlua-script.h"
#include "dlua-script-private.h"
#include "mail-storage.h"
#include "mail-storage-lua.h"
#include "mail-user.h"

#define LUA_SCRIPT_STORAGE "storage"
#define LUA_STORAGE_MAIL_USER "struct mail_user"
#define LUA_STORAGE_MAILBOX "struct mailbox"
#define LUA_STORAGE_MAIL "struct mail"

/** MAIL USER
 */

void dlua_push_mail_user(struct dlua_script *script, struct mail_user *user)
{
	luaL_checkstack(script->L, 20, "out of memory");
	/* create a table for holding few things */
	lua_createtable(script->L, 0, 20);
	luaL_setmetatable(script->L, LUA_STORAGE_MAIL_USER);

	lua_pushlightuserdata(script->L, user);
	lua_setfield(script->L, -2, "item");

#undef LUA_TABLE_SETNUMBER
#define LUA_TABLE_SETNUMBER(field) \
	lua_pushnumber(script->L, user->field); \
	lua_setfield(script->L, -2, #field);
#undef LUA_TABLE_SETBOOL
#define LUA_TABLE_SETBOOL(field) \
	lua_pushboolean(script->L, user->field); \
	lua_setfield(script->L, -2, #field);
#undef LUA_TABLE_SETSTRING
#define LUA_TABLE_SETSTRING(field) \
	lua_pushstring(script->L, user->field); \
	lua_setfield(script->L, -2, #field);

	const char *home = NULL;
	(void)mail_user_get_home(user, &home);

	lua_pushstring(script->L, home);
	lua_setfield(script->L, -2, "home");

	LUA_TABLE_SETSTRING(username);
	LUA_TABLE_SETNUMBER(uid);
	LUA_TABLE_SETNUMBER(gid);
	LUA_TABLE_SETSTRING(service);
	LUA_TABLE_SETSTRING(session_id);
	LUA_TABLE_SETNUMBER(session_create_time);

	LUA_TABLE_SETBOOL(nonexistent);
	LUA_TABLE_SETBOOL(anonymous);
	LUA_TABLE_SETBOOL(autocreated);
	LUA_TABLE_SETBOOL(mail_debug);
	LUA_TABLE_SETBOOL(fuzzy_search);
	LUA_TABLE_SETBOOL(dsyncing);
	LUA_TABLE_SETBOOL(admin);
	LUA_TABLE_SETBOOL(session_restored);
}

static struct mail_user *
lua_check_storage_mail_user(struct dlua_script *script, int arg)
{
	if (!lua_istable(script->L, arg)) {
		(void)luaL_error(script->L, "Bad argument #%d, expected %s got %s",
				 arg, LUA_STORAGE_MAIL_USER,
				 lua_typename(script->L, lua_type(script->L, arg)));
	}
	lua_pushliteral(script->L, "item");
	lua_rawget(script->L, arg);
	void *bp = (void*)lua_touserdata(script->L, -1);
	lua_pop(script->L, 1);
	return (struct mail_user*)bp;
}

static int lua_storage_mail_user_tostring(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 1);
	struct mail_user *user = lua_check_storage_mail_user(script, 1);

	lua_pushstring(L, user->username);
	return 1;
}

static int lua_storage_cmp(struct dlua_script *script)
{
	const char *name_a, *name_b;
	name_a = lua_tostring(script->L, 1);
	name_b = lua_tostring(script->L, 2);

	return strcmp(name_a, name_b);
}

static int lua_storage_mail_user_eq(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 2);
	bool res = lua_storage_cmp(script) == 0;
	lua_pushboolean(script->L, res);
	return 1;
}

static int lua_storage_mail_user_lt(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 2);
	bool res = lua_storage_cmp(script) <= 0;
	lua_pushboolean(script->L, res);
	return 1;
}

static int lua_storage_mail_user_le(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 2);
	bool res = lua_storage_cmp(script) < 0;
	lua_pushboolean(script->L, res);
	return 1;
}

static int lua_storage_mail_user_var_expand(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 2);
	struct mail_user *user = lua_check_storage_mail_user(script, 1);
	const char *error;
	const char *format = luaL_checkstring(script->L, 2);
	const struct var_expand_table *table = mail_user_var_expand_table(user);
	string_t *str = t_str_new(128);
	if (var_expand_with_funcs(str, format, table, mail_user_var_expand_func_table,
				  user, &error) < 0) {
		return luaL_error(script->L, "var_expand(%s) failed: %s",
				  format, error);
	}
	lua_pushlstring(script->L, str->data, str->used);
	return 1;
}

static int lua_storage_mail_user_plugin_getenv(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 2);
	struct mail_user *user = lua_check_storage_mail_user(script, 1);
	const char *set = lua_tostring(script->L, 2);
	const char *val = mail_user_plugin_getenv(user, set);
	lua_pushstring(script->L, val);
	return 1;
}

static int lua_storage_mail_user_mailbox_alloc(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS_IN(script, 2, 3);
	struct mail_user *user = lua_check_storage_mail_user(script, 1);
	const char *mboxname = luaL_checkstring(script->L, 2);
	enum mailbox_flags flags = 0;
	if (lua_gettop(script->L) >= 3)
		flags = luaL_checkinteger(script->L, 3);
	struct mail_namespace *ns = mail_namespace_find(user->namespaces, mboxname);
	if (ns == NULL) {
		return luaL_error(script->L, "No namespace found for mailbox %s",
				  mboxname);
	}
	struct mailbox *mbox = mailbox_alloc(ns->list, mboxname, flags);
	dlua_push_mailbox(script, mbox);
	return 1;
}

static int lua_storage_mail_user_unref(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	(void)lua_check_storage_mail_user(script, 1);

	/* reset value to NULL */
	lua_pushliteral(script->L, "item");
	lua_pushnil(script->L);
	lua_rawset(script->L, 1);

	return 0;
}

static luaL_Reg lua_storage_mail_user_methods[] = {
	{ "__tostring", lua_storage_mail_user_tostring },
	{ "__eq", lua_storage_mail_user_eq },
	{ "__lt", lua_storage_mail_user_lt },
	{ "__le", lua_storage_mail_user_le },
	{ "__gc", lua_storage_mail_user_unref },
	{ "plugin_getenv", lua_storage_mail_user_plugin_getenv },
	{ "var_expand", lua_storage_mail_user_var_expand },
	{ "mailbox", lua_storage_mail_user_mailbox_alloc },
	{ NULL, NULL }
};

static void lua_storage_mail_user_register(struct dlua_script *script)
{
	luaL_newmetatable(script->L, LUA_STORAGE_MAIL_USER);
	lua_pushvalue(script->L, -1);
	lua_setfield(script->L, -2, "__index");
	luaL_setfuncs(script->L, lua_storage_mail_user_methods, 0);
	lua_pop(script->L, 1);
}

/** End of MAIL USER
 */

/** MAILBOX
 */

#define DLUA_MAILBOX_EQUALS(a, b) mailbox_equals((a), mailbox_get_namespace(b), \
						 mailbox_get_vname(b))

void dlua_push_mailbox(struct dlua_script *script, struct mailbox *box)
{
	luaL_checkstack(script->L, 4, "out of memory");
	/* create a table for holding few things */
	lua_createtable(script->L, 0, 0);
	luaL_setmetatable(script->L, LUA_STORAGE_MAILBOX);

	lua_pushlightuserdata(script->L, box);
	lua_setfield(script->L, -2, "item");

	luaL_checkstack(script->L, 2, "out of memory");
	lua_pushstring(script->L, mailbox_get_vname(box));
	lua_setfield(script->L, -2, "vname");

	lua_pushstring(script->L, mailbox_get_name(box));
	lua_setfield(script->L, -2, "name");
}

static struct mailbox *
lua_check_storage_mailbox(struct dlua_script *script, int arg)
{
	if (!lua_istable(script->L, arg)) {
		(void)luaL_error(script->L, "Bad argument #%d, expected %s got %s",
				 arg, LUA_STORAGE_MAILBOX,
				 lua_typename(script->L, lua_type(script->L, arg)));
	}
	lua_pushliteral(script->L, "item");
	lua_rawget(script->L, arg);
	void *bp = (void*)lua_touserdata(script->L, -1);
	lua_pop(script->L, 1);
	return (struct mailbox*)bp;
}

static int lua_storage_mailbox_tostring(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 1);
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);

	lua_pushstring(L, mailbox_get_vname(mbox));
	return 1;
}

/* special case, we want to ensure this is eq when mailboxes
   are really equal */
static int lua_storage_mailbox_eq(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 2);
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);
	struct mailbox *mbox2 = lua_check_storage_mailbox(script, 2);
	lua_pushboolean(script->L, DLUA_MAILBOX_EQUALS(mbox, mbox2));
	return 1;
}

/* these compare based to mailbox vname */
static int lua_storage_mailbox_lt(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 2);
	bool res = lua_storage_cmp(script) <= 0;
	lua_pushboolean(script->L, res);
	return 1;
}

static int lua_storage_mailbox_le(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 2);
	bool res = lua_storage_cmp(script) < 0;
	lua_pushboolean(script->L, res);
	return 1;
}

static int lua_storage_mailbox_unref(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 1);
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);

	if (mbox != NULL)
		mailbox_free(&mbox);

	lua_pushlightuserdata(script->L, mbox);
	lua_pushliteral(script->L, "item");
	lua_rawset(script->L, 1);
	return 0;
}

static int lua_storage_mailbox_gc(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	(void)lua_check_storage_mailbox(script, 1);

	/* reset value to NULL */
	lua_pushliteral(script->L, "item");
	lua_pushnil(script->L);
	lua_rawset(script->L, 1);

	return 0;
}

static int lua_storage_mailbox_open(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 1);
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);

	/* try to open the box */
	if (mailbox_open(mbox) < 0) {
		return luaL_error(script->L, "mailbox_open(%s) failed: %s",
				  mailbox_get_vname(mbox),
				  mailbox_get_last_error(mbox, NULL));
	}

	return 0;
}

static int lua_storage_mailbox_close(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 1);
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);

	mailbox_close(mbox);

	return 0;
}

static int lua_storage_mailbox_sync(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS_IN(script, 2, 3);
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);
	enum mailbox_sync_flags flags = 0;

	if (lua_gettop(script->L) >= 2)
		flags = luaL_checkinteger(script->L, 2);

	if (mailbox_sync(mbox, flags) < 0) {
		const char *error = mailbox_get_last_error(mbox, NULL);
		return luaL_error(script->L, "mailbox_sync(%s) failed: %s",
				  mailbox_get_vname(mbox), error);
	}

	return 0;
}

static int lua_storage_mailbox_status(lua_State *L)
{
	struct mailbox_status status;
	const char *const *keyword;
	struct dlua_script *script = dlua_script_from_state(L);
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);
	/* get items as list of parameters */
	enum mailbox_status_items items = 0;

	if (lua_gettop(script->L) < 2)
		return luaL_error(script->L, "expecting at least 1 parameter");
	for(int i = 2; i <= lua_gettop(script->L); i++)
		items |= (unsigned int)luaL_checkinteger(script->L, i);

	i_zero(&status);
	if (mailbox_get_status(mbox, items, &status) < 0) {
		const char *error = mailbox_get_last_error(mbox, NULL);
		return luaL_error(script->L, "mailbox_get_status(%s, %u) failed: %s",
				  mbox, items, error);
	}
	/* returns a table */
	lua_createtable(script->L, 0, 20);

	lua_pushstring(script->L, mailbox_get_vname(mbox));
	lua_setfield(script->L, -2, "mailbox");

#undef LUA_TABLE_SETNUMBER
#define LUA_TABLE_SETNUMBER(field) \
	lua_pushnumber(script->L, status.field); \
	lua_setfield(script->L, -2, #field);
#undef LUA_TABLE_SETBOOL
#define LUA_TABLE_SETBOOL(field) \
	lua_pushboolean(script->L, status.field); \
	lua_setfield(script->L, -2, #field);

	LUA_TABLE_SETNUMBER(messages);
	LUA_TABLE_SETNUMBER(recent);
	LUA_TABLE_SETNUMBER(unseen);
	LUA_TABLE_SETNUMBER(uidvalidity);
	LUA_TABLE_SETNUMBER(uidnext);
	LUA_TABLE_SETNUMBER(first_unseen_seq);
	LUA_TABLE_SETNUMBER(first_recent_uid);
	LUA_TABLE_SETNUMBER(highest_modseq);
	LUA_TABLE_SETNUMBER(highest_pvt_modseq);

	LUA_TABLE_SETNUMBER(permanent_flags);
	LUA_TABLE_SETNUMBER(flags);

	LUA_TABLE_SETBOOL(permanent_keywords);
	LUA_TABLE_SETBOOL(allow_new_keywords);
	LUA_TABLE_SETBOOL(nonpermanent_modseqs);
	LUA_TABLE_SETBOOL(no_modseq_tracking);
	LUA_TABLE_SETBOOL(have_guids);
	LUA_TABLE_SETBOOL(have_save_guids);
	LUA_TABLE_SETBOOL(have_only_guid128);

	if (status.keywords != NULL && array_is_created(status.keywords)) {
		int i = 1;
		lua_createtable(script->L, array_count(status.keywords), 0);
		array_foreach(status.keywords, keyword) {
			lua_pushstring(script->L, *keyword);
			lua_rawseti(script->L, -2, i++);
		}
		lua_setfield(script->L, -2, "keywords");
	}

	return 1;
}

static luaL_Reg lua_storage_mailbox_methods[] = {
	{ "__tostring", lua_storage_mailbox_tostring },
	{ "__eq", lua_storage_mailbox_eq },
	{ "__lt", lua_storage_mailbox_lt },
	{ "__le", lua_storage_mailbox_le },
	{ "__gc", lua_storage_mailbox_gc },
	{ "free", lua_storage_mailbox_unref },
	{ "status", lua_storage_mailbox_status },
	{ "open", lua_storage_mailbox_open },
	{ "close", lua_storage_mailbox_close },
	{ "sync", lua_storage_mailbox_sync },
	{ NULL, NULL }
};

static void lua_storage_mailbox_register(struct dlua_script *script)
{
	luaL_newmetatable(script->L, LUA_STORAGE_MAILBOX);
	lua_pushvalue(script->L, -1);
	lua_setfield(script->L, -2, "__index");
	luaL_setfuncs(script->L, lua_storage_mailbox_methods, 0);
	lua_pop(script->L, 1);
}

/* MAIL */

void dlua_push_mail(struct dlua_script *script, struct mail *mail)
{
	luaL_checkstack(script->L, 20, "out of memory");
	/* create a table for holding few things */
	lua_createtable(script->L, 0, 20);
	luaL_setmetatable(script->L, LUA_STORAGE_MAIL);

	lua_pushlightuserdata(script->L, mail);
	lua_setfield(script->L, -2, "item");

#undef LUA_TABLE_SETNUMBER
#define LUA_TABLE_SETNUMBER(field) \
	lua_pushnumber(script->L, mail->field); \
	lua_setfield(script->L, -2, #field);
#undef LUA_TABLE_SETBOOL
#define LUA_TABLE_SETBOOL(field) \
	lua_pushboolean(script->L, mail->field); \
	lua_setfield(script->L, -2, #field);

	LUA_TABLE_SETNUMBER(seq);
	LUA_TABLE_SETNUMBER(uid);
	LUA_TABLE_SETBOOL(expunged);

	dlua_push_mailbox(script, mail->box);
	lua_setfield(script->L, -2, "mailbox");

}

static struct mail *
lua_check_storage_mail(struct dlua_script *script, int arg)
{
	if (!lua_istable(script->L, arg)) {
		(void)luaL_error(script->L, "Bad argument #%d, expected %s got %s",
				 arg, LUA_STORAGE_MAIL,
				 lua_typename(script->L, lua_type(script->L, arg)));
	}
	lua_pushliteral(script->L, "item");
	lua_rawget(script->L, arg);
	void *bp = (void*)lua_touserdata(script->L, -1);
	lua_pop(script->L, 1);
	return (struct mail*)bp;
}

static int lua_storage_mail_tostring(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 1);
	struct mail *mail = lua_check_storage_mail(script, 1);

	const char *str =
		t_strdup_printf("<%s:UID %u>", mailbox_get_vname(mail->box),
				mail->uid);
	lua_pushstring(script->L, str);
	return 1;
}

static int lua_storage_mail_eq(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 2);
	struct mail *mail = lua_check_storage_mail(script, 1);
	struct mail *mail2 = lua_check_storage_mail(script, 2);

	if (!DLUA_MAILBOX_EQUALS(mail->box, mail2->box))
		lua_pushboolean(script->L, FALSE);
	else
		lua_pushboolean(script->L, mail->uid != mail2->uid);
	return 1;
}

static int lua_storage_mail_lt(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 2);
	struct mail *mail = lua_check_storage_mail(script, 1);
	struct mail *mail2 = lua_check_storage_mail(script, 2);

	if (!DLUA_MAILBOX_EQUALS(mail->box, mail2->box))
		return luaL_error(script->L,
				  "For lt, Mail can only be compared within same mailbox");
	else
		lua_pushboolean(script->L, mail->uid < mail2->uid);
	return 1;
}

static int lua_storage_mail_le(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 2);
	struct mail *mail = lua_check_storage_mail(script, 1);
	struct mail *mail2 = lua_check_storage_mail(script, 2);

	if (!DLUA_MAILBOX_EQUALS(mail->box, mail2->box))
		return luaL_error(script->L,
				 "For le, mails can only be within same mailbox");
	else
		lua_pushboolean(script->L, mail->uid <= mail2->uid);

	return 1;
}

static int lua_storage_mail_gc(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	(void)lua_check_storage_mail(script, 1);

	/* reset value to NULL */
	lua_pushliteral(script->L, "item");
	lua_pushnil(script->L);
	lua_rawset(script->L, 1);

	return 0;
}

static luaL_Reg lua_storage_mail_methods[] = {
	{ "__tostring", lua_storage_mail_tostring },
	{ "__eq", lua_storage_mail_eq },
	{ "__lt", lua_storage_mail_lt },
	{ "__le", lua_storage_mail_le },
	{ "__gc", lua_storage_mail_gc },
	{ NULL, NULL }
};

static void lua_storage_mail_register(struct dlua_script *script)
{
	luaL_newmetatable(script->L, LUA_STORAGE_MAIL);
	lua_pushvalue(script->L, -1);
	lua_setfield(script->L, -2, "__index");
	luaL_setfuncs(script->L, lua_storage_mail_methods, 0);
	lua_pop(script->L, 1);
}

/* end of MAIL */

static struct dlua_table_values lua_storage_mail_storage_flags[] = {
	DLUA_TABLE_ENUM(STATUS_MESSAGES),
	DLUA_TABLE_ENUM(STATUS_RECENT),
	DLUA_TABLE_ENUM(STATUS_UIDNEXT),
	DLUA_TABLE_ENUM(STATUS_UIDVALIDITY),
	DLUA_TABLE_ENUM(STATUS_UNSEEN),
	DLUA_TABLE_ENUM(STATUS_FIRST_UNSEEN_SEQ),
	DLUA_TABLE_ENUM(STATUS_KEYWORDS),
	DLUA_TABLE_ENUM(STATUS_HIGHESTMODSEQ),
	DLUA_TABLE_ENUM(STATUS_PERMANENT_FLAGS),
	DLUA_TABLE_ENUM(STATUS_FIRST_RECENT_UID),
	DLUA_TABLE_ENUM(STATUS_HIGHESTPVTMODSEQ),

	DLUA_TABLE_ENUM(MAILBOX_FLAG_READONLY),
	DLUA_TABLE_ENUM(MAILBOX_FLAG_SAVEONLY),
	DLUA_TABLE_ENUM(MAILBOX_FLAG_DROP_RECENT),
	DLUA_TABLE_ENUM(MAILBOX_FLAG_NO_INDEX_FILES),
	DLUA_TABLE_ENUM(MAILBOX_FLAG_KEEP_LOCKED),
	DLUA_TABLE_ENUM(MAILBOX_FLAG_IGNORE_ACLS),
	DLUA_TABLE_ENUM(MAILBOX_FLAG_AUTO_CREATE),
	DLUA_TABLE_ENUM(MAILBOX_FLAG_AUTO_SUBSCRIBE),

	DLUA_TABLE_ENUM(MAILBOX_SYNC_FLAG_FULL_READ),
	DLUA_TABLE_ENUM(MAILBOX_SYNC_FLAG_FULL_WRITE),
	DLUA_TABLE_ENUM(MAILBOX_SYNC_FLAG_FAST),
	DLUA_TABLE_ENUM(MAILBOX_SYNC_FLAG_NO_EXPUNGES),
	DLUA_TABLE_ENUM(MAILBOX_SYNC_FLAG_FIX_INCONSISTENT),
	DLUA_TABLE_ENUM(MAILBOX_SYNC_FLAG_EXPUNGE),
	DLUA_TABLE_ENUM(MAILBOX_SYNC_FLAG_FORCE_RESYNC),

	DLUA_TABLE_END
};

static luaL_Reg lua_storage_methods[] = {
	{ NULL, NULL }
};

void dlua_register_mail_storage(struct dlua_script *script)
{
	/* get dlua_dovecot */
	dlua_getdovecot(script);

	/* Create table for holding values */
	lua_newtable(script->L);

	dlua_setmembers(script, lua_storage_mail_storage_flags, -1);

	/* push new metatable to stack */
	luaL_newmetatable(script->L, LUA_SCRIPT_STORAGE);
	/* this will register functions to the metatable itself */
	luaL_setfuncs(script->L, lua_storage_methods, 0);
	/* point __index to self */
	lua_pushvalue(script->L, -1);
	lua_setfield(script->L, -1, "__index");
	/* set table's metatable, pops stack */
	lua_setmetatable(script->L, -2);

	/* register table as member of dovecot */
	lua_setfield(script->L, -2, LUA_SCRIPT_STORAGE);

	lua_storage_mail_user_register(script);
	lua_storage_mailbox_register(script);
	lua_storage_mail_register(script);
}
