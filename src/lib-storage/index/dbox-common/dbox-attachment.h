#ifndef DBOX_ATTACHMENT_H
#define DBOX_ATTACHMENT_H

#include "index-attachment.h"

struct dbox_file;

void dbox_attachment_save_write_metadata(struct mail_save_context *ctx,
					 string_t *str);

/* Parse DBOX_METADATA_EXT_REF line to given array. Names are allocated
   from the given pool. */
bool dbox_attachment_parse_extref(const char *line, pool_t pool,
				  ARRAY_TYPE(mail_attachment_extref) *extrefs);
/* Build a single message body stream out of the current message and all of its
   attachments. */
int dbox_attachment_file_get_stream(struct dbox_file *file,
				    struct istream **stream);

#endif
