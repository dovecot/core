#ifndef QUOTA_SETTINGS_H
#define QUOTA_SETTINGS_H

struct quota_settings {
	pool_t pool;

	unsigned int quota_mailbox_count;
	uoff_t quota_mail_size;
	unsigned int quota_mailbox_message_count;
	const char *quota_exceeded_message;
};

struct quota_settings *quota_get_unlimited_set(void);

extern const struct setting_parser_info quota_setting_parser_info;

#endif
