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

#define LUA_SCRIPT_STORAGE "storage"
#define LUA_STORAGE_MAIL_USER "struct mail_user"

/** MAIL USER
 */

static int lua_storage_mail_user_unref(lua_State *L);

void dlua_push_mail_user(struct dlua_script *script, struct mail_user *user)
{
	luaL_checkstack(script->L, 20, "out of memory");
	/* create a table for holding few things */
	lua_createtable(script->L, 0, 20);
	luaL_setmetatable(script->L, LUA_STORAGE_MAIL_USER);

	mail_user_ref(user);
	struct mail_user **ptr = lua_newuserdata(script->L, sizeof(struct mail_user*));
	*ptr = user;
	lua_createtable(script->L, 0, 1);
	lua_pushcfunction(script->L, lua_storage_mail_user_unref);
	lua_setfield(script->L, -2, "__gc");
	lua_setmetatable(script->L, -2);
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
	struct mail_user **bp = lua_touserdata(script->L, -1);
	lua_pop(script->L, 1);
	return *bp;
}

static int lua_storage_mail_user_tostring(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 1);
	struct mail_user *user = lua_check_storage_mail_user(script, 1);

	lua_pushstring(L, user->username);
	return 1;
}

int lua_storage_cmp(struct dlua_script *script)
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
	struct mail_user **ptr = lua_touserdata(script->L, 1);
	if (*ptr != NULL)
		mail_user_unref(ptr);
	*ptr = NULL;
	return 0;
}

static const char *lua_storage_mail_user_metadata_key(const char *key)
{
	if (str_begins(key, "/private/")) {
		return t_strdup_printf("/private/%s%s",
				       MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER,
				       key + 9);
	} else if (str_begins(key, "/shared/")) {
		return t_strdup_printf("/shared/%s%s",
				       MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER,
				       key + 8);
	}
	return NULL;
}

static int lua_storage_mail_user_metadata_get(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	if (lua_gettop(script->L) < 2)
		return luaL_error(script->L, "expecting at least 1 parameter");
	struct mail_user *user = lua_check_storage_mail_user(script, 1);

	const char *value, *error;
	size_t value_len;
	int ret, i, top = lua_gettop(script->L);

	/* fetch INBOX, as user metadata is stored there */
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *mbox = mailbox_alloc(ns->list, "INBOX",
					     MAILBOX_FLAG_READONLY);

	if (mailbox_open(mbox) < 0) {
		error = mailbox_get_last_error(mbox, NULL);
		mailbox_free(&mbox);
		return luaL_error(script->L, "Cannot open INBOX: %s", error);
	}

	ret = 0;
	for(i = 2; i <= top; i++) {
		/* reformat key */
		const char *key = lua_tostring(script->L, i);

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
			lua_pushnil(script->L);
		} else {
			lua_pushlstring(script->L, value, value_len);
		}
	}

	mailbox_free(&mbox);

	if (ret < 0)
		return luaL_error(script->L, "%s", error);

	i_assert(i>=2);
	return i-2;
}

static int
lua_storage_mail_user_set_metadata_unset(struct dlua_script *script,
					 struct mail_user *user,
					 const char *key, const char *value,
					 size_t value_len)
{
	const char *error;

	/* reformat key */
	if ((key = lua_storage_mail_user_metadata_key(key)) == NULL) {
		return luaL_error(script->L, "Invalid key prefix, must be "
					     "/private/ or /shared/");
	}

	/* fetch INBOX, as user metadata is stored there */
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *mbox = mailbox_alloc(ns->list, "INBOX", 0);

	if (mailbox_open(mbox) < 0) {
		error = mailbox_get_last_error(mbox, NULL);
		mailbox_free(&mbox);
		return luaL_error(script->L,
				  "Cannot open INBOX: %s", error);
	}

	if (lua_storage_mailbox_attribute_set(mbox, key, value, value_len,
					      &error) < 0) {
		mailbox_free(&mbox);
		return luaL_error(script->L,
				  "Cannot get attribute: %s", error);
	}

	mailbox_free(&mbox);
	return 0;
}

static int lua_storage_mail_user_metadata_set(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 3);
	struct mail_user *user = lua_check_storage_mail_user(script, 1);
	const char *key = luaL_checkstring(script->L, 2);
	const char *value;
	size_t value_len;

	value = lua_tolstring(script->L, 3, &value_len);

	return lua_storage_mail_user_set_metadata_unset(script, user, key,
							value, value_len);
}

static int lua_storage_mail_user_metadata_unset(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	DLUA_REQUIRE_ARGS(script, 2);
	struct mail_user *user = lua_check_storage_mail_user(script, 1);
	const char *key = luaL_checkstring(script->L, 2);

	return lua_storage_mail_user_set_metadata_unset(script, user, key, NULL, 0);
}

static int lua_storage_mail_user_metadata_list(lua_State *L)
{
	struct dlua_script *script = dlua_script_from_state(L);
	if (lua_gettop(script->L) < 2)
		return luaL_error(script->L, "expecting at least 1 parameter");
	struct mail_user *user = lua_check_storage_mail_user(script, 1);
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
		return luaL_error(script->L,
				  "Cannot open INBOX: %s", error);
	}

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
			lua_createtable(script->L, 0, array_count(&items));
			array_foreach(&items, item) {
				char *ptr;
				char *key = t_strdup_noconst(item->key);
				if ((ptr = strstr(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER)) != NULL) {
					const char *endp = ptr+strlen(MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER);
					memmove(ptr, endp, strlen(endp));
					memset(ptr+strlen(endp), '\0', 1);
				}
				/* push value */
				lua_pushlstring(script->L, item->value,
						item->value_len);
				/* set field */
				lua_setfield(script->L, -2, key);
			}
		}
	} T_END;

	mailbox_free(&mbox);

	if (ret == -1)
		return luaL_error(script->L, "%s", error);

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

	DLUA_TABLE_STRING("MAILBOX_ATTRIBUTE_PREFIX_DOVECOT",
			  MAILBOX_ATTRIBUTE_PREFIX_DOVECOT),
	DLUA_TABLE_STRING("MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT",
			  MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT),
	DLUA_TABLE_STRING("MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER",
			  MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER),

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
