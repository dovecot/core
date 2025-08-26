#ifndef IMAP_PROGRESS_H
#define IMAP_PROGRESS_H

const char *
imap_storage_callback_line(const struct mail_storage_progress_details *dtl,
			   const char *tag);

#endif
