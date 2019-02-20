#ifndef MAIL_STORAGE_LUA_H
#define MAIL_STORAGE_LUA_H 1

struct mail_user;
struct mailbox;
struct mail;
struct dlua_script;

void dlua_register_mail_storage(struct dlua_script *script);
void dlua_push_mail_user(struct dlua_script *script, struct mail_user *user);
void dlua_push_mailbox(struct dlua_script *script, struct mailbox *box);
void dlua_push_mail(struct dlua_script *script, struct mail *mail);

#endif
