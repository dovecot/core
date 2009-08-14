#ifndef ALL_SETTINGS_H
#define ALL_SETTINGS_H

struct all_settings_root {
	const char *module_name;
	struct setting_parser_info *root;
};
extern const struct all_settings_root all_roots[];

#endif
