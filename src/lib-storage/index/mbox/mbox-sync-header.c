/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str.h"
#include "write-full.h"
#include "message-parser.h"
#include "mail-index.h"
#include "mbox-sync-private.h"

#include <unistd.h>

struct mbox_flag_type {
	char chr;
	enum mail_flags flag;
};

#define MBOX_NONRECENT MAIL_RECENT /* kludgy */

#define STATUS_FLAGS_MASK (MAIL_SEEN|MBOX_NONRECENT)
static struct mbox_flag_type status_flags[] = {
	{ 'R', MAIL_SEEN },
	{ 'O', MBOX_NONRECENT },
	{ 0, 0 }
};

#define XSTATUS_FLAGS_MASK (MAIL_ANSWERED|MAIL_FLAGGED|MAIL_DRAFT|MAIL_DELETED)
static struct mbox_flag_type xstatus_flags[] = {
	{ 'A', MAIL_ANSWERED },
	{ 'F', MAIL_FLAGGED },
	{ 'T', MAIL_DRAFT },
	{ 'D', MAIL_DELETED },
	{ 0, 0 }
};

struct header_func {
	const char *header;
	int (*func)(struct mbox_sync_mail_context *ctx,
		    struct message_header_line *hdr);
};

static enum mail_flags mbox_flag_find(struct mbox_flag_type *flags, char chr)
{
	int i;

	for (i = 0; flags[i].chr != 0; i++) {
		if (flags[i].chr == chr)
			return flags[i].flag;
	}

	return 0;
}

static void status_flags_append(struct mbox_sync_mail_context *ctx,
				struct mbox_flag_type *flags_list)
{
	int i;

	for (i = 0; flags_list[i].chr != 0; i++) {
		if ((ctx->mail_flags & flags_list[i].flag) != 0) {
			str_append_c(ctx->header, flags_list[i].chr);
			ctx->mail_flags &= ~flags_list[i].flag;
		}
	}
}

static int parse_status_flags(struct mbox_sync_mail_context *ctx,
			      struct message_header_line *hdr,
			      struct mbox_flag_type *flags_list)
{
	size_t i, start, end;
	int j;
        enum mail_flags flags, flags_mask;

	flags = 0;
	for (i = 0; i < hdr->full_value_len; i++)
		flags |= mbox_flag_find(flags_list, hdr->full_value[i]);

	flags_mask = 0;
	for (j = 0; flags_list[j].chr != 0; j++)
		flags_mask |= flags_list[j].flag;

	/* see if anything changed */
	if (flags == (ctx->mail_flags & flags_mask)) {
		ctx->mail_flags &= ~flags_mask;
		return FALSE;
	}

	start = str_len(ctx->header);
	str_append(ctx->header, hdr->name);
	str_append(ctx->header, ": ");
	end = str_len(ctx->header);

	status_flags_append(ctx, flags_list);

	for (i = 0; i < hdr->full_value_len; i++) {
		switch (hdr->full_value[i]) {
		case ' ':
		case '\t':
		case '\r':
		case '\n':
			break;
		default:
			if (mbox_flag_find(flags_list, hdr->full_value[i]) != 0)
				break;

			/* unknown, keep it */
			str_append_c(ctx->header, hdr->full_value[i]);
			break;
		}
	}

	if (str_len(ctx->header) != end)
		str_append_c(ctx->header, '\n');
	else
		str_truncate(ctx->header, start);
	return TRUE;
}

static int parse_status(struct mbox_sync_mail_context *ctx,
			struct message_header_line *hdr)
{
	return parse_status_flags(ctx, hdr, status_flags);
}

static int parse_x_status(struct mbox_sync_mail_context *ctx,
			  struct message_header_line *hdr)
{
	return parse_status_flags(ctx, hdr, xstatus_flags);
}

static int parse_x_imap_base(struct mbox_sync_mail_context *ctx,
			     struct message_header_line *hdr)
{
	ctx->ximapbase_pos = buffer_get_used_size(ctx->header);
	// FIXME: check it
	//ctx->extra_space += 1;
	return FALSE;
}

static int parse_x_keywords(struct mbox_sync_mail_context *ctx,
			    struct message_header_line *hdr)
{
	ctx->xkeywords_pos = buffer_get_used_size(ctx->header);
	// FIXME: update it
        //ctx->extra_space += 1;
	return FALSE;
}

static int parse_content_length(struct mbox_sync_mail_context *ctx,
				struct message_header_line *hdr)
{
	uoff_t value = 0;
	size_t i;

	if (ctx->content_length != (uoff_t)-1) {
		/* duplicate */
		return TRUE;
	}

	for (i = 0; i < hdr->full_value_len; i++) {
		if (hdr->full_value[i] < '0' || hdr->full_value[i] > '9')
			break;
		value = value*10 + (hdr->full_value[i] - '0');
	}

	for (; i < hdr->full_value_len; i++) {
		if (hdr->full_value[i] != ' ' && hdr->full_value[i] != '\t') {
			/* broken value */
			return TRUE;
		}
	}

	ctx->content_length = value;
	return FALSE;
}

static int parse_x_uid(struct mbox_sync_mail_context *ctx,
		       struct message_header_line *hdr)
{
	uint32_t value = 0;
	size_t i, extra_space = 0;

	if (ctx->uid != 0) {
		/* duplicate */
		return TRUE;
	}

	for (i = 0; i < hdr->full_value_len; i++) {
		if (hdr->full_value[i] < '0' || hdr->full_value[i] > '9')
			break;
		value = value*10 + (hdr->full_value[i] - '0');
	}

	for (; i < hdr->full_value_len; i++) {
		if (hdr->full_value[i] != ' ' && hdr->full_value[i] != '\t') {
			/* broken value */
			return TRUE;
		}
		extra_space++;
	}

	if (value <= ctx->parent->prev_msg_uid) {
		/* broken - UIDs must be growing */
		return TRUE;
	}

	ctx->uid = value;
	ctx->extra_space += extra_space;
	ctx->xuid_pos = buffer_get_used_size(ctx->header);
	return FALSE;
}

static struct header_func header_funcs[] = {
	{ "Content-Length", parse_content_length },
	{ "Status", parse_status },
	{ "X-IMAPbase", parse_x_imap_base },
	{ "X-Keywords", parse_x_keywords },
	{ "X-Status", parse_x_status },
	{ "X-UID", parse_x_uid },
	{ NULL, NULL }
};

static struct header_func *header_func_find(const char *header)
{
	int i;

	for (i = 0; header_funcs[i].header != NULL; i++) {
		if (strcasecmp(header_funcs[i].header, header) == 0)
			return &header_funcs[i];
	}
	return NULL;
}

void mbox_sync_mail_parse_headers(struct mbox_sync_mail_context *ctx)
{
	struct message_header_parser_ctx *hdr_ctx;
	struct message_header_line *hdr;
        struct header_func *func;

        ctx->header_first_change = (size_t)-1;
	ctx->header_last_change = (size_t)-1;

	ctx->xuid_pos = (size_t)-1;
	ctx->xkeywords_pos = (size_t)-1;

	ctx->content_length = (uoff_t)-1;
	str_truncate(ctx->header, 0);

	hdr_ctx = message_parse_header_init(ctx->parent->input, NULL);
	while ((hdr = message_parse_header_next(hdr_ctx)) != NULL) {
		if (hdr->eoh) {
			ctx->have_eoh = 1;
			break;
		}

		func = header_func_find(hdr->name);
		if (func != NULL) {
			if (hdr->continues) {
				hdr->use_full_value = TRUE;
				continue;
			}
			if (func->func(ctx, hdr)) {
				/* we modified this header */
				if (ctx->header_first_change == (size_t)-1) {
					ctx->header_first_change =
					      buffer_get_used_size(ctx->header);
				}
				ctx->header_last_change = (size_t)-1;
			} else {
				func = NULL;
			}
		}

		if (func == NULL) {
			if (ctx->header_last_change == (size_t)-1) {
				/* we may be able to stop rewriting here */
				ctx->header_last_change =
					buffer_get_used_size(ctx->header);
			}
			if (!hdr->continued) {
				str_append(ctx->header, hdr->name);
				str_append(ctx->header, ": ");
			}
			buffer_append(ctx->header, hdr->full_value,
				      hdr->full_value_len);
			if (!hdr->no_newline)
				str_append_c(ctx->header, '\n');
		}
	}
	message_parse_header_deinit(hdr_ctx);
}

void mbox_sync_mail_add_missing_headers(struct mbox_sync_mail_context *ctx)
{
	size_t old_hdr_size, new_hdr_size, size;
	const char *str;
	void *p;
	int changed;

	old_hdr_size = ctx->body_offset - ctx->hdr_offset;
	new_hdr_size = str_len(ctx->header) + ctx->have_eoh;

	changed = FALSE;
	if (ctx->uid == 0) {
		ctx->xuid_pos = buffer_get_used_size(ctx->header);
		str_printfa(ctx->header, "X-UID: %u\n",
			    ctx->parent->next_uid++);
	}

	if ((ctx->mail_flags & STATUS_FLAGS_MASK) != 0) {
		str_append(ctx->header, "Status: ");
		status_flags_append(ctx, status_flags);
		str_append_c(ctx->header, '\n');
	}

	if ((ctx->mail_flags & XSTATUS_FLAGS_MASK) != 0) {
		str_append(ctx->header, "X-Status: ");
		status_flags_append(ctx, xstatus_flags);
		str_append_c(ctx->header, '\n');
	}

	if (ctx->seq == 1 && ctx->base_uidvalidity == 0) {
		ctx->ximapbase_pos = buffer_get_used_size(ctx->header);
		str_printfa(ctx->header, "X-IMAPbase: %u %u",
			    ctx->parent->hdr->uid_validity,
			    ctx->parent->next_uid);

		/* if we can get away by adding only a little space, do it.
		   otherwise give a lot of extra */
		size = str_len(ctx->header) + ctx->have_eoh + 1 -
			ctx->extra_space/2;
		if (size <= old_hdr_size)
			size = old_hdr_size - size;
		else
			size = 256;

		p = buffer_append_space_unsafe(ctx->header, size);
		memset(p, ' ', size);
		str_append_c(ctx->header, '\n');
	}

	/* write Content-Length if we have space */
	if (ctx->content_length == (uoff_t)-1) {
		str = t_strdup_printf("Content-Length: %"PRIuUOFF_T"\n",
				      ctx->body_size);
		size = buffer_get_used_size(ctx->header) + ctx->have_eoh -
			ctx->extra_space;
		if (size > old_hdr_size || size + strlen(str) <= old_hdr_size)
			str_append(ctx->header, str);
	}

	/* Create X-Keywords header if it's not there and we have space */
	if (ctx->xkeywords_pos == (size_t)-1) {
		size = buffer_get_used_size(ctx->header) + ctx->have_eoh -
			ctx->extra_space;
		if (size > old_hdr_size ||
		    size + sizeof("X-Keywords: ") <= old_hdr_size) {
			ctx->xkeywords_pos = buffer_get_used_size(ctx->header);
			str_append(ctx->header, "X-Keywords: \n");
		}
	}

	if (buffer_get_used_size(ctx->header) != new_hdr_size) {
		if (ctx->header_first_change == (size_t)-1)
			ctx->header_first_change = new_hdr_size;
		ctx->header_last_change = (size_t)-1;
		new_hdr_size = buffer_get_used_size(ctx->header) +
			ctx->have_eoh;
	}

	if (ctx->header_first_change == (size_t)-1) {
		/* no headers had to be modified */
		return;
	}

	if (ctx->have_eoh)
		str_append_c(ctx->header, '\n');
}

static void mbox_sync_headers_add_space(struct mbox_sync_mail_context *ctx,
					size_t size)
{
	size_t data_size, pos;
	const unsigned char *data;
	void *p;

	/* Append at the end of X-Keywords header,
	   or X-UID if it doesn't exist */
	pos = ctx->xkeywords_pos != (size_t)-1 ?
		ctx->xkeywords_pos : ctx->xuid_pos;

	data = buffer_get_data(ctx->header, &data_size);
	while (pos < data_size && data[pos] != '\n')
		pos++;

	buffer_copy(ctx->header, pos + size,
		    ctx->header, pos, (size_t)-1);
	p = buffer_get_space_unsafe(ctx->header, pos, size);
	memset(p, ' ', size);
	ctx->extra_space += size;

	if (ctx->header_first_change > pos)
		ctx->header_first_change = pos;
	ctx->header_last_change = (size_t)-1;
}

static void mbox_sync_header_remove_space(struct mbox_sync_mail_context *ctx,
					  size_t pos, size_t *size)
{
	const unsigned char *data;
	size_t data_size, end, nonspace;

	/* find the end of the lwsp */
	nonspace = pos;
	data = str_data(ctx->header);
	data_size = str_len(ctx->header);
	for (end = pos; end < data_size; end++) {
		if (data[end] == '\n') {
			if (end+1 == data_size || !IS_LWSP(data[end+1]))
				break;
		} else {
			if (!IS_LWSP(data[end]))
				nonspace = end;
		}
	}

	/* and remove what we can */
	nonspace++;
	if (end-nonspace < *size) {
		str_delete(ctx->header, nonspace, end-nonspace);
		*size -= end-nonspace;
	} else {
		str_delete(ctx->header, nonspace, *size);
		*size = 0;
	}
}

static void mbox_sync_headers_remove_space(struct mbox_sync_mail_context *ctx,
					   size_t size)
{
	if (ctx->xkeywords_pos != (size_t)-1)
		mbox_sync_header_remove_space(ctx, ctx->xkeywords_pos, &size);
	if (ctx->xuid_pos != (size_t)-1 && size > 0)
		mbox_sync_header_remove_space(ctx, ctx->xuid_pos, &size);
	if (ctx->ximapbase_pos != (size_t)-1 && size > 0)
		mbox_sync_header_remove_space(ctx, ctx->ximapbase_pos, &size);
	i_assert(size == 0);
}

int mbox_sync_try_rewrite_headers(struct mbox_sync_mail_context *ctx,
				  uoff_t *missing_space_r)
{
	size_t old_hdr_size, new_hdr_size;
	const unsigned char *data;

	old_hdr_size = ctx->body_offset - ctx->hdr_offset;
	new_hdr_size = str_len(ctx->header);

	/* do we have enough space? */
	if (new_hdr_size < old_hdr_size)
		mbox_sync_headers_add_space(ctx, old_hdr_size - new_hdr_size);
	else if (new_hdr_size > old_hdr_size) {
		if (ctx->extra_space < new_hdr_size - old_hdr_size) {
			*missing_space_r = new_hdr_size - old_hdr_size -
				ctx->extra_space;
			return 0;
		}

		ctx->extra_space -= new_hdr_size - old_hdr_size;
		mbox_sync_headers_remove_space(ctx, new_hdr_size -
					       old_hdr_size);
	}

	i_assert(ctx->header_first_change != (size_t)-1);

	if (ctx->header_last_change != (size_t)-1)
		str_truncate(ctx->header, ctx->header_last_change);

	data = str_data(ctx->header);
        new_hdr_size = str_len(ctx->header);
	if (pwrite_full(ctx->parent->fd, data + ctx->header_first_change,
			new_hdr_size,
			ctx->hdr_offset + ctx->header_first_change) < 0) {
		// FIXME: error handling
		return -1;
	}
	*missing_space_r = 0;
	return 0;
}
