#ifndef MAIL_STORAGE_LUA_PRIVATE_H
#define MAIL_STORAGE_LUA_PRIVATE_H 1

#define DLUA_MAILBOX_EQUALS(a, b) \
	mailbox_equals((a), mailbox_get_namespace(b), mailbox_get_vname(b))

void lua_storage_mail_register(struct dlua_script *script);

#endif
