#ifndef __MBOX_SYNC_PRIVATE_H
#define __MBOX_SYNC_PRIVATE_H

#include "mail-index.h"

struct mbox_flag_type {
	char chr;
	enum mail_flags flag;
};

enum header_position {
	MBOX_HDR_STATUS,
	MBOX_HDR_X_IMAPBASE,
	MBOX_HDR_X_KEYWORDS,
	MBOX_HDR_X_STATUS,
	MBOX_HDR_X_UID,

        MBOX_HDR_COUNT
};

#define MBOX_NONRECENT MAIL_RECENT /* kludgy */

#define STATUS_FLAGS_MASK (MAIL_SEEN|MBOX_NONRECENT)
#define XSTATUS_FLAGS_MASK (MAIL_ANSWERED|MAIL_FLAGGED|MAIL_DRAFT|MAIL_DELETED)
extern struct mbox_flag_type mbox_status_flags[];
extern struct mbox_flag_type mbox_xstatus_flags[];

struct mbox_mail {
	uint32_t uid;
	uint8_t flags;
	keywords_mask_t keywords;

	uoff_t space_offset; /* if space is negative, points to beginning */
	off_t space;
	uoff_t body_size;
};

struct mbox_sync_mail_context {
	struct mbox_sync_context *sync_ctx;
	struct mbox_mail *mail;

	uint32_t seq;
	uoff_t hdr_offset, body_offset;

	size_t header_first_change, header_last_change;
	string_t *header;

	uint32_t base_uid_validity, base_uid_last;
	uoff_t content_length;

	size_t hdr_pos[MBOX_HDR_COUNT];

	unsigned int have_eoh:1;
	unsigned int need_rewrite:1;
};

struct mbox_sync_context {
	struct istream *file_input;
	struct istream *input;
	int fd;

	const struct mail_index_header *hdr;

	uint32_t prev_msg_uid, next_uid;
};

void mbox_sync_parse_next_mail(struct istream *input,
			       struct mbox_sync_mail_context *ctx);
void mbox_sync_update_header(struct mbox_sync_mail_context *ctx,
			     struct mail_index_sync_rec *update);
int mbox_sync_try_rewrite(struct mbox_sync_mail_context *ctx);
int mbox_sync_rewrite(struct mbox_sync_context *sync_ctx, buffer_t *mails_buf,
		      uint32_t first_seq, uint32_t last_seq, off_t extra_space);

int mbox_move(struct mbox_sync_context *sync_ctx,
	      uoff_t dest, uoff_t source, uoff_t size);

#endif
