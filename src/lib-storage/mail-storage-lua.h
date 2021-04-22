#ifndef MAIL_STORAGE_LUA_H
#define MAIL_STORAGE_LUA_H 1

#include "dlua-script.h"
#include "dlua-script-private.h"

struct mail_user;
struct mailbox;
struct mail;
struct dlua_script;

void dlua_register_mail_storage(struct dlua_script *script);
void dlua_push_mail_user(lua_State *L, struct mail_user *user);
void dlua_push_mailbox(lua_State *L, struct mailbox *box);
void dlua_push_mail(lua_State *L, struct mail *mail);

#endif
