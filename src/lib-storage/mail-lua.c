/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "array.h"
#include "var-expand.h"
#include "dlua-script.h"
#include "dlua-script-private.h"
#include "mail-storage.h"
#include "mailbox-attribute.h"
#include "mail-storage-lua.h"
#include "mail-storage-lua-private.h"
#include "mail-user.h"

#define LUA_STORAGE_MAIL "struct mail"

void dlua_push_mail(lua_State *L, struct mail *mail)
{
	luaL_checkstack(L, 20, "out of memory");
	/* create a table for holding few things */
	lua_createtable(L, 0, 20);
	luaL_setmetatable(L, LUA_STORAGE_MAIL);

	lua_pushlightuserdata(L, mail);
	lua_setfield(L, -2, "item");

#undef LUA_TABLE_SET_NUMBER
#define LUA_TABLE_SET_NUMBER(field) \
	lua_pushnumber(L, mail->field); \
	lua_setfield(L, -2, #field);
#undef LUA_TABLE_SET_BOOL
#define LUA_TABLE_SET_BOOL(field) \
	lua_pushboolean(L, mail->field); \
	lua_setfield(L, -2, #field);

	LUA_TABLE_SET_NUMBER(seq);
	LUA_TABLE_SET_NUMBER(uid);
	LUA_TABLE_SET_BOOL(expunged);

	dlua_push_mailbox(L, mail->box);
	lua_setfield(L, -2, "mailbox");

}

static struct mail *
lua_check_storage_mail(lua_State *L, int arg)
{
	if (!lua_istable(L, arg)) {
		(void)luaL_error(L, "Bad argument #%d, expected %s got %s",
				 arg, LUA_STORAGE_MAIL,
				 lua_typename(L, lua_type(L, arg)));
	}
	lua_pushliteral(L, "item");
	lua_rawget(L, arg);
	void *bp = (void*)lua_touserdata(L, -1);
	lua_pop(L, 1);
	return (struct mail*)bp;
}

static int lua_storage_mail_tostring(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	struct mail *mail = lua_check_storage_mail(L, 1);

	const char *str =
		t_strdup_printf("<%s:UID %u>", mailbox_get_vname(mail->box),
				mail->uid);
	lua_pushstring(L, str);
	return 1;
}

static int lua_storage_mail_eq(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct mail *mail = lua_check_storage_mail(L, 1);
	struct mail *mail2 = lua_check_storage_mail(L, 2);

	if (!DLUA_MAILBOX_EQUALS(mail->box, mail2->box))
		lua_pushboolean(L, FALSE);
	else
		lua_pushboolean(L, mail->uid != mail2->uid);
	return 1;
}

static int lua_storage_mail_lt(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct mail *mail = lua_check_storage_mail(L, 1);
	struct mail *mail2 = lua_check_storage_mail(L, 2);

	if (!DLUA_MAILBOX_EQUALS(mail->box, mail2->box))
		return luaL_error(L,
				  "For lt, Mail can only be compared within same mailbox");
	else
		lua_pushboolean(L, mail->uid < mail2->uid);
	return 1;
}

static int lua_storage_mail_le(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct mail *mail = lua_check_storage_mail(L, 1);
	struct mail *mail2 = lua_check_storage_mail(L, 2);

	if (!DLUA_MAILBOX_EQUALS(mail->box, mail2->box))
		return luaL_error(L,
				 "For le, mails can only be within same mailbox");
	else
		lua_pushboolean(L, mail->uid <= mail2->uid);

	return 1;
}

static int lua_storage_mail_gc(lua_State *L)
{
	(void)lua_check_storage_mail(L, 1);

	/* reset value to NULL */
	lua_pushliteral(L, "item");
	lua_pushnil(L);
	lua_rawset(L, 1);

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

void lua_storage_mail_register(struct dlua_script *script)
{
	luaL_newmetatable(script->L, LUA_STORAGE_MAIL);
	lua_pushvalue(script->L, -1);
	lua_setfield(script->L, -2, "__index");
	luaL_setfuncs(script->L, lua_storage_mail_methods, 0);
	lua_pop(script->L, 1);
}
