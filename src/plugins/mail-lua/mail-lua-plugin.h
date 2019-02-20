#ifndef MAIL_LUA_PLUGIN_H
#define MAIL_LUA_PLUGIN_H 1

struct dlua_script;
struct mail_user;
struct module;

void mail_lua_plugin_init(struct module *module);
void mail_lua_plugin_deinit(void);

bool mail_lua_plugin_get_script(struct mail_user *user,
				struct dlua_script **script_r);

#endif
