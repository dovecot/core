#ifndef MBOX_MD5_H
#define MBOX_MD5_H

struct message_header_line;

struct mbox_md5_vfuncs {
	struct mbox_md5_context *(*init)(void);
	void (*more)(struct mbox_md5_context *ctx,
		     struct message_header_line *hdr);
	void (*finish)(struct mbox_md5_context *ctx,
		       unsigned char result[16]);
};

extern struct mbox_md5_vfuncs mbox_md5_apop3d;
extern struct mbox_md5_vfuncs mbox_md5_all;

#endif
