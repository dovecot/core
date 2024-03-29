#ifndef MAILDIR_SETTINGS_H
#define MAILDIR_SETTINGS_H

struct maildir_settings {
	pool_t pool;
	bool maildir_copy_with_hardlinks;
	bool maildir_very_dirty_syncs;
	bool maildir_broken_filename_sizes;
	bool maildir_empty_new;
};

extern const struct setting_parser_info maildir_setting_parser_info;

#endif
