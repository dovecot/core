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

#define LUA_STORAGE_MAILBOX "struct mailbox"

static int lua_storage_mailbox_gc(lua_State *L);

void dlua_push_mailbox(struct dlua_script *script, struct mailbox *box)
{
	luaL_checkstack(script->L, 4, "out of memory");
	/* create a table for holding few things */
	lua_createtable(script->L, 0, 0);
	luaL_setmetatable(script->L, LUA_STORAGE_MAILBOX);

	struct mailbox **ptr = lua_newuserdata(script->L, sizeof(struct mailbox*));
	*ptr = box;
	lua_createtable(script->L, 0, 1);
	lua_pushcfunction(script->L, lua_storage_mailbox_gc);
	lua_setfield(script->L, -2, "__gc");
	lua_setmetatable(script->L, -2);
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
	struct mailbox **bp = lua_touserdata(script->L, -1);
	lua_pop(script->L, 1);
	return *bp;
}

static int lua_storage_mailbox_tostring(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(L, 1);
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);

	lua_pushstring(L, mailbox_get_vname(mbox));
	return 1;
}

/* special case, we want to ensure this is eq when mailboxes
   are really equal */
static int lua_storage_mailbox_eq(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(L, 2);
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);
	struct mailbox *mbox2 = lua_check_storage_mailbox(script, 2);
	lua_pushboolean(script->L, DLUA_MAILBOX_EQUALS(mbox, mbox2));
	return 1;
}

/* these compare based to mailbox vname */
static int lua_storage_mailbox_lt(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(L, 2);
	bool res = lua_storage_cmp(script) <= 0;
	lua_pushboolean(script->L, res);
	return 1;
}

static int lua_storage_mailbox_le(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(L, 2);
	bool res = lua_storage_cmp(script) < 0;
	lua_pushboolean(script->L, res);
	return 1;
}

static int lua_storage_mailbox_unref(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(L, 1);
	/* fetch item from table */
	lua_pushliteral(script->L, "item");
	lua_rawget(script->L, 1);
	struct mailbox **mbox = lua_touserdata(script->L, -1);
	if (*mbox != NULL)
		mailbox_free(mbox);
	*mbox = NULL;
	lua_pop(script->L, 1);
	return 0;
}

static int lua_storage_mailbox_gc(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	struct mailbox **mbox = lua_touserdata(script->L, 1);

	if (*mbox != NULL)
		mailbox_free(mbox);

	return 0;
}

static int lua_storage_mailbox_open(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(L, 1);
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
	DLUA_REQUIRE_ARGS(L, 1);
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);

	mailbox_close(mbox);

	return 0;
}

static int lua_storage_mailbox_sync(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS_IN(L, 1, 2);
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

static int lua_storage_mailbox_metadata_get(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	if (lua_gettop(script->L) < 2)
		return luaL_error(script->L, "expecting at least 1 parameter");
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);
	const char *value, *error;
	size_t value_len;
	int ret, i, top = lua_gettop(script->L);

	ret = 0;
	for(i = 2; i <= top; i++) {
		const char *key = lua_tostring(script->L, i);
		if (key == NULL) {
			ret = -1;
			error = t_strdup_printf("expected string at #%d", i);
			break;
		}

		if ((ret = lua_storage_mailbox_attribute_get(mbox, key, &value,
							     &value_len, &error)) < 0) {
			break;
		} else if (ret == 0) {
			lua_pushnil(script->L);
		} else {
			lua_pushlstring(script->L, value, value_len);
		}
	}

	if (ret < 0)
		return luaL_error(script->L, "%s", error);

	/* return number of pushed items */
	i_assert(i>=2);
	return i-2;
}

static int lua_storage_mailbox_metadata_set(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(L, 3);
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);
	const char *key = luaL_checkstring(script->L, 2);
	const char *value, *error;
	size_t value_len;

	value = lua_tolstring(script->L, 3, &value_len);

	if (lua_storage_mailbox_attribute_set(mbox, key, value, value_len, &error) < 0)
		return luaL_error(script->L,
				  t_strdup_printf("Cannot set attribute: %s", error));

	return 0;
}

static int lua_storage_mailbox_metadata_unset(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(L, 2);
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);
	const char *key = luaL_checkstring(script->L, 2);
	const char *error;

	if (lua_storage_mailbox_attribute_set(mbox, key, NULL, 0,  &error) < 0)
		return luaL_error(script->L,
				  t_strdup_printf("Cannot unset attribute: %s", error));

	return 0;
}

static int lua_storage_mailbox_metadata_list(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	if (lua_gettop(script->L) < 2)
		return luaL_error(script->L, "expecting at least 1 parameter");
	struct mailbox *mbox = lua_check_storage_mailbox(script, 1);
	const struct lua_storage_keyvalue *item;
	const char *error;
	ARRAY_TYPE(lua_storage_keyvalue) items;
	int i, ret;

	T_BEGIN {
		t_array_init(&items, 1);

		ret = 0;
		for(i = 2; i <= lua_gettop(script->L); i++) {
			const char *key = lua_tostring(script->L, i);

			if (key == NULL) {
				ret = -1;
				error = t_strdup_printf("expected string at #%d", i);
				break;
			}

			if (lua_storage_mailbox_attribute_list(mbox, key, &items,
							       &error) < 0) {
				ret = -1;
				break;
			}
		}

		if (ret == 0) {
			lua_createtable(script->L, 0, array_count(&items));
			array_foreach(&items, item) {
				/* push value */
				lua_pushlstring(script->L, item->value,
						item->value_len);
				/* set field */
				lua_setfield(script->L, -2, item->key);
			}
		}
	} T_END;

	if (ret == -1)
		return luaL_error(script->L, "%s", error);

	/* stack should have table with items */
	return 1;
}

static luaL_Reg lua_storage_mailbox_methods[] = {
	{ "__tostring", lua_storage_mailbox_tostring },
	{ "__eq", lua_storage_mailbox_eq },
	{ "__lt", lua_storage_mailbox_lt },
	{ "__le", lua_storage_mailbox_le },
	{ "free", lua_storage_mailbox_unref },
	{ "status", lua_storage_mailbox_status },
	{ "open", lua_storage_mailbox_open },
	{ "close", lua_storage_mailbox_close },
	{ "sync", lua_storage_mailbox_sync },
	{ "metadata_get", lua_storage_mailbox_metadata_get },
	{ "metadata_set", lua_storage_mailbox_metadata_set },
	{ "metadata_unset", lua_storage_mailbox_metadata_unset },
	{ "metadata_list", lua_storage_mailbox_metadata_list },
	{ NULL, NULL }
};

void lua_storage_mailbox_register(struct dlua_script *script)
{
	luaL_newmetatable(script->L, LUA_STORAGE_MAILBOX);
	lua_pushvalue(script->L, -1);
	lua_setfield(script->L, -2, "__index");
	luaL_setfuncs(script->L, lua_storage_mailbox_methods, 0);
	lua_pop(script->L, 1);
}
