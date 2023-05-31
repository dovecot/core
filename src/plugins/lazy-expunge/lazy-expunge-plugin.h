#ifndef LAZY_EXPUNGE_PLUGIN_H
#define LAZY_EXPUNGE_PLUGIN_H

struct module;

struct lazy_expunge_settings {
	pool_t pool;

	bool lazy_expunge_only_last_instance;
	const char *lazy_expunge_mailbox;
};

extern const struct setting_parser_info lazy_expunge_setting_parser_info;

void lazy_expunge_plugin_init(struct module *module);
void lazy_expunge_plugin_deinit(void);

#endif
