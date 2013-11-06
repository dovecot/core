#ifndef DBOX_ATTACHMENT_H
#define DBOX_ATTACHMENT_H

#include "index-attachment.h"

struct dbox_file;

void dbox_attachment_save_write_metadata(struct mail_save_context *ctx,
					 string_t *str);

/* Build a single message body stream out of the current message and all of its
   attachments. */
int dbox_attachment_file_get_stream(struct dbox_file *file,
				    struct istream **stream);

#endif
