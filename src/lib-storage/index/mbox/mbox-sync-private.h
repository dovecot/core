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

struct mbox_sync_mail {
	uint32_t uid;
	uint8_t flags;
	keywords_mask_t keywords;

	uoff_t from_offset;
	uoff_t offset; /* if space <= 0, points to beginning */
	off_t space;
	uoff_t body_size;
};

struct mbox_sync_mail_context {
	struct mbox_sync_context *sync_ctx;
	struct mbox_sync_mail mail;

	uint32_t seq;
	uoff_t from_offset, hdr_offset, body_offset;

	size_t header_first_change, header_last_change;
	string_t *header;

	uoff_t content_length;

	size_t hdr_pos[MBOX_HDR_COUNT];

	unsigned int have_eoh:1;
	unsigned int need_rewrite:1;
	unsigned int seen_imapbase:1;
	unsigned int pseudo:1;
	unsigned int updated:1;
};

struct mbox_sync_context {
	struct index_mailbox *ibox;
	struct istream *input, *file_input;
	int fd;

	string_t *header, *from_line;
	uint32_t base_uid_validity, base_uid_last;
	uint32_t prev_msg_uid, next_uid, first_uid;
	off_t expunged_space;
};

int mbox_sync(struct index_mailbox *ibox, int last_commit);
void mbox_sync_parse_next_mail(struct istream *input,
			       struct mbox_sync_mail_context *ctx,
			       int rewriting);
void mbox_sync_update_header(struct mbox_sync_mail_context *ctx,
			     buffer_t *syncs_buf);
void mbox_sync_update_header_from(struct mbox_sync_mail_context *ctx,
				  const struct mbox_sync_mail *mail);
int mbox_sync_try_rewrite(struct mbox_sync_mail_context *ctx, off_t move_diff);
int mbox_sync_rewrite(struct mbox_sync_context *sync_ctx, buffer_t *mails_buf,
		      uint32_t first_seq, uint32_t last_seq, off_t extra_space);

int mbox_move(struct mbox_sync_context *sync_ctx,
	      uoff_t dest, uoff_t source, uoff_t size);

#endif
