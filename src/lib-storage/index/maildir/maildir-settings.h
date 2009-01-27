#ifndef MAILDIR_SETTINGS_H
#define MAILDIR_SETTINGS_H

struct maildir_settings {
	bool maildir_stat_dirs;
	bool maildir_copy_with_hardlinks;
	bool maildir_copy_preserve_filename;
};

const struct setting_parser_info *maildir_get_setting_parser_info(void);

#endif
