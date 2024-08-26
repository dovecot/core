#ifndef QUOTA_SETTINGS_H
#define QUOTA_SETTINGS_H

/* <settings checks> */
#define QUOTA_WARNING_RESOURCE_STORAGE "storage"
#define QUOTA_WARNING_RESOURCE_MESSAGE "message"

#define QUOTA_WARNING_THRESHOLD_OVER "over"
#define QUOTA_WARNING_THRESHOLD_UNDER "under"
/* </settings checks> */

struct quota_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) quota_roots;

	/* Globals: */

	unsigned int quota_mailbox_count;
	uoff_t quota_mail_size;
	unsigned int quota_mailbox_message_count;
	const char *quota_exceeded_message;
};

struct quota_root_settings {
	pool_t pool;

	ARRAY_TYPE(const_string) quota_warnings;

	/* Client-visible name of the quota root */
	const char *quota_name;
	const char *quota_driver;
	/* If TRUE, quota is not tracked at all (for this mailbox). This is
	   typically set only for specific mailboxes or namespaces. Note that
	   this differs from unlimited quota, which still tracks the quota,
	   even if it is not enforced. */
	bool quota_ignore;
	/* IF TRUE, quota is ignored only when quota is unlimited. */
	bool quota_ignore_unlimited;
	/* Whether to actually enforce quota limits. */
	bool quota_enforce;
	/* Quota root is hidden (to e.g. IMAP GETQUOTAROOT) */
	bool quota_hidden;
	/* Quota storage size is counted as:
	   quota_storage_size * quota_storage_percentage / 100 +
	   quota_storage_extra. */
	uoff_t quota_storage_size;
	unsigned int quota_storage_percentage;
	uoff_t quota_storage_extra;
	/* If user is under quota before saving a mail, allow the last mail to
	   bring the user over quota by this many bytes. This is only used for
	   mail delivery sessions (lda, lmtp). */
	uoff_t quota_storage_grace;
	/* Quota messages count is counted as:
	   quota_message_count * quota_message_percentage / 100. */
	unsigned int quota_message_count;
	unsigned int quota_message_percentage;

	/* For quota warnings: */

	/* Name for the warning. This is only for identification in the
	   configuration. */
	const char *quota_warning_name;
	/* Specifies the quota resource the warning tracks
	   (storage / message) */
	const char *quota_warning_resource;
	/* Specifies whether the warning is executed when going over the limit
	   or back under the limit. */
	const char *quota_warning_threshold;

	/* For quota_over_status: */

	bool quota_over_status_lazy_check;
	const char *quota_over_status_current;
	const char *quota_over_status_mask;

	/* Generated: */

	const struct quota_backend *backend;
};

struct quota_settings *quota_get_unlimited_set(void);

extern const struct setting_parser_info quota_setting_parser_info;
extern const struct setting_parser_info quota_root_setting_parser_info;

#endif
