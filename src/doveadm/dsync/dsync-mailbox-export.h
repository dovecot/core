#ifndef DSYNC_MAILBOX_EXPORT_H
#define DSYNC_MAILBOX_EXPORT_H

enum dsync_mailbox_exporter_flags {
	DSYNC_MAILBOX_EXPORTER_FLAG_AUTO_EXPORT_MAILS	= 0x01,
	DSYNC_MAILBOX_EXPORTER_FLAG_MAILS_HAVE_GUIDS	= 0x02
};

struct dsync_mailbox_exporter *
dsync_mailbox_export_init(struct mailbox *box,
			  struct dsync_transaction_log_scan *log_scan,
			  uint32_t last_common_uid,
			  enum dsync_mailbox_exporter_flags flags);
const struct dsync_mailbox_attribute *
dsync_mailbox_export_next_attr(struct dsync_mailbox_exporter *exporter);
const struct dsync_mail_change *
dsync_mailbox_export_next(struct dsync_mailbox_exporter *exporter);

void dsync_mailbox_export_want_mail(struct dsync_mailbox_exporter *exporter,
				    const struct dsync_mail_request *request);
const struct dsync_mail *
dsync_mailbox_export_next_mail(struct dsync_mailbox_exporter *exporter);
int dsync_mailbox_export_deinit(struct dsync_mailbox_exporter **exporter,
				const char **error_r);

const char *dsync_mailbox_export_get_proctitle(struct dsync_mailbox_exporter *exporter);

#endif
