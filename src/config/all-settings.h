#ifndef ALL_SETTINGS_H
#define ALL_SETTINGS_H

struct config_setting_parser_list {
	const char *module_name;
	struct setting_parser_info *root;
	struct setting_parser_context *parser;
	void *settings;
};
ARRAY_DEFINE_TYPE(config_setting_parsers, struct config_setting_parser_list *);

extern struct config_setting_parser_list config_setting_parsers[];

#endif
