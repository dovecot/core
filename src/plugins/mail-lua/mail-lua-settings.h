#ifndef MAIL_LUA_SETTINGS_H
#define MAIL_LUA_SETTINGS_H

/* <settings checks> */
#define MAIL_LUA_FILTER "mail_lua"
/* </settings checks> */

struct mail_lua_settings {
	pool_t pool;
};

extern const struct setting_parser_info mail_lua_setting_parser_info;

#endif
