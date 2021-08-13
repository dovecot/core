/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "array.h"
#include "var-expand.h"
#include "mail-storage.h"
#include "mailbox-attribute.h"
#include "mail-storage-lua.h"
#include "mail-storage-lua-private.h"
#include "mail-user.h"

#define LUA_STORAGE_MAILBOX "struct mailbox"

static int lua_storage_mailbox_gc(lua_State *L);

void dlua_push_mailbox(lua_State *L, struct mailbox *box)
{
	luaL_checkstack(L, 4, "out of memory");
	/* create a table for holding few things */
	lua_createtable(L, 0, 0);
	luaL_setmetatable(L, LUA_STORAGE_MAILBOX);

	struct mailbox **ptr = lua_newuserdata(L, sizeof(struct mailbox*));
	*ptr = box;
	lua_createtable(L, 0, 1);
	lua_pushcfunction(L, lua_storage_mailbox_gc);
	lua_setfield(L, -2, "__gc");
	lua_setmetatable(L, -2);
	lua_setfield(L, -2, "item");

	luaL_checkstack(L, 2, "out of memory");
	lua_pushstring(L, mailbox_get_vname(box));
	lua_setfield(L, -2, "vname");

	lua_pushstring(L, mailbox_get_name(box));
	lua_setfield(L, -2, "name");
}

static struct mailbox *
lua_check_storage_mailbox(lua_State *L, int arg)
{
	if (!lua_istable(L, arg)) {
		(void)luaL_error(L, "Bad argument #%d, expected %s got %s",
				 arg, LUA_STORAGE_MAILBOX,
				 lua_typename(L, lua_type(L, arg)));
	}
	lua_pushliteral(L, "item");
	lua_rawget(L, arg);
	struct mailbox **bp = lua_touserdata(L, -1);
	lua_pop(L, 1);
	return *bp;
}

static int lua_storage_mailbox_tostring(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	struct mailbox *mbox = lua_check_storage_mailbox(L, 1);

	lua_pushstring(L, mailbox_get_vname(mbox));
	return 1;
}

/* special case, we want to ensure this is eq when mailboxes
   are really equal */
static int lua_storage_mailbox_eq(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct mailbox *mbox = lua_check_storage_mailbox(L, 1);
	struct mailbox *mbox2 = lua_check_storage_mailbox(L, 2);
	lua_pushboolean(L, DLUA_MAILBOX_EQUALS(mbox, mbox2));
	return 1;
}

/* these compare based to mailbox vname */
static int lua_storage_mailbox_lt(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	bool res = lua_storage_cmp(L) <= 0;
	lua_pushboolean(L, res);
	return 1;
}

static int lua_storage_mailbox_le(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	bool res = lua_storage_cmp(L) < 0;
	lua_pushboolean(L, res);
	return 1;
}

static int lua_storage_mailbox_unref(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	/* fetch item from table */
	lua_pushliteral(L, "item");
	lua_rawget(L, 1);
	struct mailbox **mbox = lua_touserdata(L, -1);
	if (*mbox != NULL)
		mailbox_free(mbox);
	*mbox = NULL;
	lua_pop(L, 1);
	return 0;
}

static int lua_storage_mailbox_gc(lua_State *L)
{
	struct mailbox **mbox = lua_touserdata(L, 1);

	if (*mbox != NULL)
		mailbox_free(mbox);

	return 0;
}

static int lua_storage_mailbox_open(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	struct mailbox *mbox = lua_check_storage_mailbox(L, 1);

	/* try to open the box */
	if (mailbox_open(mbox) < 0) {
		return luaL_error(L, "mailbox_open(%s) failed: %s",
				  mailbox_get_vname(mbox),
				  mailbox_get_last_error(mbox, NULL));
	}

	return 0;
}

static int lua_storage_mailbox_close(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	struct mailbox *mbox = lua_check_storage_mailbox(L, 1);

	mailbox_close(mbox);

	return 0;
}

static int lua_storage_mailbox_sync(lua_State *L)
{
	DLUA_REQUIRE_ARGS_IN(L, 1, 2);
	struct mailbox *mbox = lua_check_storage_mailbox(L, 1);
	enum mailbox_sync_flags flags = 0;

	if (lua_gettop(L) >= 2)
		flags = luaL_checkinteger(L, 2);

	if (mailbox_sync(mbox, flags) < 0) {
		const char *error = mailbox_get_last_error(mbox, NULL);
		return luaL_error(L, "mailbox_sync(%s) failed: %s",
				  mailbox_get_vname(mbox), error);
	}

	return 0;
}

static int lua_storage_mailbox_status(lua_State *L)
{
	struct mailbox_status status;
	const char *keyword;
	struct mailbox *mbox = lua_check_storage_mailbox(L, 1);
	/* get items as list of parameters */
	enum mailbox_status_items items = 0;

	if (lua_gettop(L) < 2)
		return luaL_error(L, "expecting at least 1 parameter");
	for(int i = 2; i <= lua_gettop(L); i++)
		items |= (unsigned int)luaL_checkinteger(L, i);

	i_zero(&status);
	if (mailbox_get_status(mbox, items, &status) < 0) {
		const char *error = mailbox_get_last_error(mbox, NULL);
		return luaL_error(L, "mailbox_get_status(%s, %u) failed: %s",
				  mailbox_get_vname(mbox), items, error);
	}
	/* returns a table */
	lua_createtable(L, 0, 20);

	lua_pushstring(L, mailbox_get_vname(mbox));
	lua_setfield(L, -2, "mailbox");

#undef LUA_TABLE_SET_NUMBER
#define LUA_TABLE_SET_NUMBER(field) \
	lua_pushnumber(L, status.field); \
	lua_setfield(L, -2, #field);
#undef LUA_TABLE_SET_BOOL
#define LUA_TABLE_SET_BOOL(field) \
	lua_pushboolean(L, status.field); \
	lua_setfield(L, -2, #field);

	LUA_TABLE_SET_NUMBER(messages);
	LUA_TABLE_SET_NUMBER(recent);
	LUA_TABLE_SET_NUMBER(unseen);
	LUA_TABLE_SET_NUMBER(uidvalidity);
	LUA_TABLE_SET_NUMBER(uidnext);
	LUA_TABLE_SET_NUMBER(first_unseen_seq);
	LUA_TABLE_SET_NUMBER(first_recent_uid);
	LUA_TABLE_SET_NUMBER(highest_modseq);
	LUA_TABLE_SET_NUMBER(highest_pvt_modseq);

	LUA_TABLE_SET_NUMBER(permanent_flags);
	LUA_TABLE_SET_NUMBER(flags);

	LUA_TABLE_SET_BOOL(permanent_keywords);
	LUA_TABLE_SET_BOOL(allow_new_keywords);
	LUA_TABLE_SET_BOOL(nonpermanent_modseqs);
	LUA_TABLE_SET_BOOL(no_modseq_tracking);
	LUA_TABLE_SET_BOOL(have_guids);
	LUA_TABLE_SET_BOOL(have_save_guids);
	LUA_TABLE_SET_BOOL(have_only_guid128);

	if (status.keywords != NULL && array_is_created(status.keywords)) {
		int i = 1;
		lua_createtable(L, array_count(status.keywords), 0);
		array_foreach_elem(status.keywords, keyword) {
			lua_pushstring(L, keyword);
			lua_rawseti(L, -2, i++);
		}
		lua_setfield(L, -2, "keywords");
	}

	return 1;
}

static int lua_storage_mailbox_metadata_get(lua_State *L)
{
	if (lua_gettop(L) < 2)
		return luaL_error(L, "expecting at least 1 parameter");
	struct mailbox *mbox = lua_check_storage_mailbox(L, 1);
	const char *value, *error;
	size_t value_len;
	int ret, i, top = lua_gettop(L);

	ret = 0;
	for(i = 2; i <= top; i++) {
		const char *key = lua_tostring(L, i);
		if (key == NULL) {
			ret = -1;
			error = t_strdup_printf("expected string at #%d", i);
			break;
		}

		if ((ret = lua_storage_mailbox_attribute_get(mbox, key, &value,
							     &value_len, &error)) < 0) {
			break;
		} else if (ret == 0) {
			lua_pushnil(L);
		} else {
			lua_pushlstring(L, value, value_len);
		}
	}

	if (ret < 0)
		return luaL_error(L, "%s", error);

	/* return number of pushed items */
	i_assert(i>=2);
	return i-2;
}

static int lua_storage_mailbox_metadata_set(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 3);
	struct mailbox *mbox = lua_check_storage_mailbox(L, 1);
	const char *key = luaL_checkstring(L, 2);
	const char *value, *error;
	size_t value_len;

	value = lua_tolstring(L, 3, &value_len);

	if (lua_storage_mailbox_attribute_set(mbox, key, value, value_len, &error) < 0)
		return luaL_error(L, "Cannot set attribute: %s", error);

	return 0;
}

static int lua_storage_mailbox_metadata_unset(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct mailbox *mbox = lua_check_storage_mailbox(L, 1);
	const char *key = luaL_checkstring(L, 2);
	const char *error;

	if (lua_storage_mailbox_attribute_set(mbox, key, NULL, 0,  &error) < 0)
		return luaL_error(L, "Cannot unset attribute: %s", error);

	return 0;
}

static int lua_storage_mailbox_metadata_list(lua_State *L)
{
	if (lua_gettop(L) < 2)
		return luaL_error(L, "expecting at least 1 parameter");
	struct mailbox *mbox = lua_check_storage_mailbox(L, 1);
	const struct lua_storage_keyvalue *item;
	const char *error;
	ARRAY_TYPE(lua_storage_keyvalue) items;
	int i, ret;

	T_BEGIN {
		t_array_init(&items, 1);

		ret = 0;
		for(i = 2; i <= lua_gettop(L); i++) {
			const char *key = lua_tostring(L, i);

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
			lua_createtable(L, 0, array_count(&items));
			array_foreach(&items, item) {
				/* push value */
				lua_pushlstring(L, item->value,
						item->value_len);
				/* set field */
				lua_setfield(L, -2, item->key);
			}
		}
	} T_END;

	if (ret == -1)
		return luaL_error(L, "%s", error);

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
