#ifndef MBOX_MD5_H
#define MBOX_MD5_H

struct mbox_md5_context *mbox_md5_init(void);
void mbox_md5_continue(struct mbox_md5_context *ctx,
		       struct message_header_line *hdr);
void mbox_md5_finish(struct mbox_md5_context *ctx,
		     unsigned char result[16]);

#endif
