#ifndef DSYNC_MAILBOX_EXPORT_H
#define DSYNC_MAILBOX_EXPORT_H

enum dsync_mailbox_exporter_flags {
	DSYNC_MAILBOX_EXPORTER_FLAG_AUTO_EXPORT_MAILS	= 0x01,
	DSYNC_MAILBOX_EXPORTER_FLAG_MAILS_HAVE_GUIDS	= 0x02,
	DSYNC_MAILBOX_EXPORTER_FLAG_MINIMAL_DMAIL_FILL	= 0x04,
	DSYNC_MAILBOX_EXPORTER_FLAG_TIMESTAMPS		= 0x08,
	DSYNC_MAILBOX_EXPORTER_FLAG_HDR_HASH_V2		= 0x10,
	DSYNC_MAILBOX_EXPORTER_FLAG_NO_HDR_HASHES	= 0x20
};

struct dsync_mailbox_exporter *
dsync_mailbox_export_init(struct mailbox *box,
			  struct dsync_transaction_log_scan *log_scan,
			  uint32_t last_common_uid,
			  enum dsync_mailbox_exporter_flags flags);
/* Returns 1 if attribute was returned, 0 if no more attributes, -1 on error */
int dsync_mailbox_export_next_attr(struct dsync_mailbox_exporter *exporter,
				   const struct dsync_mailbox_attribute **attr_r);
/* Returns 1 if change was returned, 0 if no more changes, -1 on error */
int dsync_mailbox_export_next(struct dsync_mailbox_exporter *exporter,
			      const struct dsync_mail_change **change_r);

void dsync_mailbox_export_want_mail(struct dsync_mailbox_exporter *exporter,
				    const struct dsync_mail_request *request);
/* Returns 1 if mail was returned, 0 if no more mails, -1 on error */
int dsync_mailbox_export_next_mail(struct dsync_mailbox_exporter *exporter,
				   const struct dsync_mail **mail_r);
int dsync_mailbox_export_deinit(struct dsync_mailbox_exporter **exporter,
				const char **errstr_r, enum mail_error *error_r);

const char *dsync_mailbox_export_get_proctitle(struct dsync_mailbox_exporter *exporter);

#endif
