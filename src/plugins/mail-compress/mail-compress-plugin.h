#ifndef MAIL_COMPRESS_PLUGIN_H
#define MAIL_COMPRESS_PLUGIN_H

struct mail_compress_settings {
	pool_t pool;
	const char *mail_compress_write_method;
};

extern const struct setting_parser_info mail_compress_setting_parser_info;

void mail_compress_plugin_init(struct module *module);
void mail_compress_plugin_deinit(void);

#endif
