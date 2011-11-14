#ifndef MAILDIR_SETTINGS_H
#define MAILDIR_SETTINGS_H

struct maildir_settings {
	bool maildir_copy_with_hardlinks;
	bool maildir_very_dirty_syncs;
	bool maildir_broken_filename_sizes;
};

const struct setting_parser_info *maildir_get_setting_parser_info(void);

#endif
