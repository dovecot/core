#ifndef INDEX_ATTACHMENT_H
#define INDEX_ATTACHMENT_H

#include "sha1.h"

struct fs;
struct mail_save_context;
struct mail_storage;

struct mail_attachment_extref {
	/* path without attachment_dir/ prefix */
	const char *path;
	/* offset in input stream where part begins */
	uoff_t start_offset;
	uoff_t size;

	/* If non-zero, this attachment was saved as base64-decoded and it
	   need to be encoded back before presenting it to client. Each line
	   (except last one) consists of this many base64 blocks (4 chars of
	   base64 encoded data). */
	unsigned int base64_blocks_per_line;
	/* Line feeds are CRLF instead of LF */
	bool base64_have_crlf;
};
ARRAY_DEFINE_TYPE(mail_attachment_extref, struct mail_attachment_extref);

void index_attachment_save_begin(struct mail_save_context *ctx,
				 struct fs *fs, struct istream *input);
int index_attachment_save_continue(struct mail_save_context *ctx);
int index_attachment_save_finish(struct mail_save_context *ctx);
void index_attachment_save_free(struct mail_save_context *ctx);
const ARRAY_TYPE(mail_attachment_extref) *
index_attachment_save_get_extrefs(struct mail_save_context *ctx);

/* Delete a given attachment name from storage
   (name is same as mail_attachment_extref.name). */
int index_attachment_delete(struct mail_storage *storage,
			    struct fs *fs, const char *name);

#endif
