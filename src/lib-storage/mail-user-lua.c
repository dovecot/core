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

#define LUA_STORAGE_MAIL_USER "struct mail_user"

static int lua_storage_mail_user_unref(lua_State *L);

void dlua_push_mail_user(lua_State *L, struct mail_user *user)
{
	luaL_checkstack(L, 20, "out of memory");
	/* create a table for holding few things */
	lua_createtable(L, 0, 20);
	luaL_setmetatable(L, LUA_STORAGE_MAIL_USER);

	mail_user_ref(user);
	struct mail_user **ptr = lua_newuserdata(L, sizeof(struct mail_user*));
	*ptr = user;
	lua_createtable(L, 0, 1);
	lua_pushcfunction(L, lua_storage_mail_user_unref);
	lua_setfield(L, -2, "__gc");
	lua_setmetatable(L, -2);
	lua_setfield(L, -2, "item");

#undef LUA_TABLE_SET_NUMBER
#define LUA_TABLE_SET_NUMBER(field) \
	lua_pushnumber(L, user->field); \
	lua_setfield(L, -2, #field);
#undef LUA_TABLE_SET_BOOL
#define LUA_TABLE_SET_BOOL(field) \
	lua_pushboolean(L, user->field); \
	lua_setfield(L, -2, #field);
#undef LUA_TABLE_SET_STRING
#define LUA_TABLE_SET_STRING(field) \
	lua_pushstring(L, user->field); \
	lua_setfield(L, -2, #field);

	const char *home = NULL;
	(void)mail_user_get_home(user, &home);

	lua_pushstring(L, home);
	lua_setfield(L, -2, "home");

	LUA_TABLE_SET_STRING(username);
	LUA_TABLE_SET_NUMBER(uid);
	LUA_TABLE_SET_NUMBER(gid);
	LUA_TABLE_SET_STRING(service);
	LUA_TABLE_SET_STRING(session_id);
	LUA_TABLE_SET_NUMBER(session_create_time);

	LUA_TABLE_SET_BOOL(nonexistent);
	LUA_TABLE_SET_BOOL(anonymous);
	LUA_TABLE_SET_BOOL(autocreated);
	LUA_TABLE_SET_BOOL(mail_debug);
	LUA_TABLE_SET_BOOL(fuzzy_search);
	LUA_TABLE_SET_BOOL(dsyncing);
	LUA_TABLE_SET_BOOL(admin);
	LUA_TABLE_SET_BOOL(session_restored);
}

static struct mail_user *
lua_check_storage_mail_user(lua_State *L, int arg)
{
	if (!lua_istable(L, arg)) {
		(void)luaL_error(L, "Bad argument #%d, expected %s got %s",
				 arg, LUA_STORAGE_MAIL_USER,
				 lua_typename(L, lua_type(L, arg)));
	}
	lua_pushliteral(L, "item");
	lua_rawget(L, arg);
	struct mail_user **bp = lua_touserdata(L, -1);
	lua_pop(L, 1);
	return *bp;
}

static int lua_storage_mail_user_tostring(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 1);
	struct mail_user *user = lua_check_storage_mail_user(L, 1);

	lua_pushstring(L, user->username);
	return 1;
}

int lua_storage_cmp(lua_State *L)
{
	const char *name_a, *name_b;
	name_a = lua_tostring(L, 1);
	name_b = lua_tostring(L, 2);

	return strcmp(name_a, name_b);
}

static int lua_storage_mail_user_eq(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	bool res = lua_storage_cmp(L) == 0;
	lua_pushboolean(L, res);
	return 1;
}

static int lua_storage_mail_user_lt(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	bool res = lua_storage_cmp(L) <= 0;
	lua_pushboolean(L, res);
	return 1;
}

static int lua_storage_mail_user_le(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	bool res = lua_storage_cmp(L) < 0;
	lua_pushboolean(L, res);
	return 1;
}

static int lua_storage_mail_user_var_expand(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct mail_user *user = lua_check_storage_mail_user(L, 1);
	const char *error;
	const char *format = luaL_checkstring(L, 2);
	const struct var_expand_table *table = mail_user_var_expand_table(user);
	string_t *str = t_str_new(128);
	if (var_expand_with_funcs(str, format, table, mail_user_var_expand_func_table,
				  user, &error) < 0) {
		return luaL_error(L, "var_expand(%s) failed: %s",
				  format, error);
	}
	lua_pushlstring(L, str->data, str->used);
	return 1;
}

static int lua_storage_mail_user_plugin_getenv(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct mail_user *user = lua_check_storage_mail_user(L, 1);
	const char *set = lua_tostring(L, 2);
	const char *val = mail_user_plugin_getenv(user, set);
	lua_pushstring(L, val);
	return 1;
}

static int lua_storage_mail_user_mailbox_alloc(lua_State *L)
{
	DLUA_REQUIRE_ARGS_IN(L, 2, 3);
	struct mail_user *user = lua_check_storage_mail_user(L, 1);
	const char *mboxname = luaL_checkstring(L, 2);
	enum mailbox_flags flags = 0;
	if (lua_gettop(L) >= 3)
		flags = luaL_checkinteger(L, 3);
	struct mail_namespace *ns = mail_namespace_find(user->namespaces, mboxname);
	if (ns == NULL) {
		return luaL_error(L, "No namespace found for mailbox %s",
				  mboxname);
	}
	struct mailbox *mbox = mailbox_alloc(ns->list, mboxname, flags);
	dlua_push_mailbox(L, mbox);
	return 1;
}

static int lua_storage_mail_user_unref(lua_State *L)
{
	struct mail_user **ptr = lua_touserdata(L, 1);
	if (*ptr != NULL)
		mail_user_unref(ptr);
	*ptr = NULL;
	return 0;
}

static const char *lua_storage_mail_user_metadata_key(const char *key)
{
	if (str_begins(key, "/private/", &key)) {
		return t_strdup_printf("/private/%s%s",
				       MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER,
				       key);
	} else if (str_begins(key, "/shared/", &key)) {
		return t_strdup_printf("/shared/%s%s",
				       MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER,
				       key);
	}
	return NULL;
}

static int lua_storage_mail_user_metadata_get(lua_State *L)
{
	if (lua_gettop(L) < 2)
		return luaL_error(L, "expecting at least 1 parameter");
	struct mail_user *user = lua_check_storage_mail_user(L, 1);

	const char *value, *error;
	size_t value_len;
	int ret, i, top = lua_gettop(L);

	/* fetch INBOX, as user metadata is stored there */
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *mbox = mailbox_alloc(ns->list, "INBOX",
					     MAILBOX_FLAG_READONLY);

	if (mailbox_open(mbox) < 0) {
		error = mailbox_get_last_error(mbox, NULL);
		mailbox_free(&mbox);
		return luaL_error(L, "Cannot open INBOX: %s", error);
	}

	ret = 0;
	for(i = 2; i <= top; i++) {
		/* reformat key */
		const char *key = lua_tostring(L, i);

		if (key == NULL) {
			ret = -1;
			error = t_strdup_printf("expected string at #%d", i);
			break;
		}

		if ((key = lua_storage_mail_user_metadata_key(key)) == NULL) {
			ret = -1;
			error = "Invalid key prefix, must be "
				"/private/ or /shared/";
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

	mailbox_free(&mbox);

	if (ret < 0)
		return luaL_error(L, "%s", error);

	i_assert(i>=2);
	return i-2;
}

static int
lua_storage_mail_user_set_metadata_unset(lua_State *L, struct mail_user *user,
					 const char *key, const char *value,
					 size_t value_len)
{
	const char *error;

	/* reformat key */
	if ((key = lua_storage_mail_user_metadata_key(key)) == NULL) {
		return luaL_error(L, "Invalid key prefix, must be "
				     "/private/ or /shared/");
	}

	/* fetch INBOX, as user metadata is stored there */
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *mbox = mailbox_alloc(ns->list, "INBOX", 0);

	if (mailbox_open(mbox) < 0) {
		error = mailbox_get_last_error(mbox, NULL);
		mailbox_free(&mbox);
		return luaL_error(L, "Cannot open INBOX: %s", error);
	}

	if (lua_storage_mailbox_attribute_set(mbox, key, value, value_len,
					      &error) < 0) {
		mailbox_free(&mbox);
		return luaL_error(L, "Cannot get attribute: %s", error);
	}

	mailbox_free(&mbox);
	return 0;
}

static int lua_storage_mail_user_metadata_set(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 3);
	struct mail_user *user = lua_check_storage_mail_user(L, 1);
	const char *key = luaL_checkstring(L, 2);
	const char *value;
	size_t value_len;

	value = lua_tolstring(L, 3, &value_len);

	return lua_storage_mail_user_set_metadata_unset(L, user, key,
							value, value_len);
}

static int lua_storage_mail_user_metadata_unset(lua_State *L)
{
	DLUA_REQUIRE_ARGS(L, 2);
	struct mail_user *user = lua_check_storage_mail_user(L, 1);
	const char *key = luaL_checkstring(L, 2);

	return lua_storage_mail_user_set_metadata_unset(L, user, key, NULL, 0);
}

static int lua_storage_mail_user_metadata_list(lua_State *L)
{
	if (lua_gettop(L) < 2)
		return luaL_error(L, "expecting at least 1 parameter");
	struct mail_user *user = lua_check_storage_mail_user(L, 1);
	const struct lua_storage_keyvalue *item;
	const char *error;
	ARRAY_TYPE(lua_storage_keyvalue) items;
	int i, ret;

	/* fetch INBOX, as user metadata is stored there */
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *mbox = mailbox_alloc(ns->list, "INBOX", 0);

	if (mailbox_open(mbox) < 0) {
		error = mailbox_get_last_error(mbox, NULL);
		mailbox_free(&mbox);
		return luaL_error(L, "Cannot open INBOX: %s", error);
	}

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

			if ((key = lua_storage_mail_user_metadata_key(key)) == NULL) {
				ret = -1;
				error = "Invalid key prefix, must be "
					"/private/ or /shared/";
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
				char *ptr;
				char *key = t_strdup_noconst(item->key);
				if ((ptr = strstr(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER)) != NULL) {
					const char *endp = ptr+strlen(MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER);
					memmove(ptr, endp, strlen(endp));
					memset(ptr+strlen(endp), '\0', 1);
				}
				/* push value */
				lua_pushlstring(L, item->value,
						item->value_len);
				/* set field */
				lua_setfield(L, -2, key);
			}
		}
	} T_END;

	mailbox_free(&mbox);

	if (ret == -1)
		return luaL_error(L, "%s", error);

	/* stack should have table with items */
	return 1;
}

static luaL_Reg lua_storage_mail_user_methods[] = {
	{ "__tostring", lua_storage_mail_user_tostring },
	{ "__eq", lua_storage_mail_user_eq },
	{ "__lt", lua_storage_mail_user_lt },
	{ "__le", lua_storage_mail_user_le },
	{ "plugin_getenv", lua_storage_mail_user_plugin_getenv },
	{ "var_expand", lua_storage_mail_user_var_expand },
	{ "mailbox", lua_storage_mail_user_mailbox_alloc },
	{ "metadata_get", lua_storage_mail_user_metadata_get },
	{ "metadata_set", lua_storage_mail_user_metadata_set },
	{ "metadata_unset", lua_storage_mail_user_metadata_unset },
	{ "metadata_list", lua_storage_mail_user_metadata_list },
	{ NULL, NULL }
};

void lua_storage_mail_user_register(struct dlua_script *script)
{
	luaL_newmetatable(script->L, LUA_STORAGE_MAIL_USER);
	lua_pushvalue(script->L, -1);
	lua_setfield(script->L, -2, "__index");
	luaL_setfuncs(script->L, lua_storage_mail_user_methods, 0);
	lua_pop(script->L, 1);
}
