#ifndef MBOX_SETTINGS_H
#define MBOX_SETTINGS_H

struct mbox_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) mbox_read_locks;
	ARRAY_TYPE(const_string) mbox_write_locks;
	unsigned int mbox_lock_timeout;
	unsigned int mbox_dotlock_change_timeout;
	uoff_t mbox_min_index_size;
	bool mbox_dirty_syncs;
	bool mbox_very_dirty_syncs;
	bool mbox_lazy_writes;
	const char *mbox_md5;
};

extern const struct setting_parser_info mbox_setting_parser_info;

#endif
