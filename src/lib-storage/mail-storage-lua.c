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
	dlua_get_dovecot(script->L);

	/* Create table for holding values */
	lua_newtable(script->L);

	dlua_set_members(script->L, lua_storage_mail_storage_flags, -1);

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

	/* pop dlua_dovecot from stack */
	lua_pop(script->L, 1);
}
