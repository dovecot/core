/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* Implemented against draft-ietf-imapext-sort-10 and
   draft-ietf-imapext-thread-12 */

#include "lib.h"
#include "buffer.h"
#include "charset-utf8.h"
#include "message-header-decode.h"
#include "imap-base-subject.h"

static void pack_whitespace(buffer_t *buf)
{
	char *data, *dest;
	bool last_lwsp;

	data = buffer_get_modifiable_data(buf, NULL);

	/* check if we need to do anything */
	while (*data != '\0') {
		if (*data == '\t' || *data == '\n' || *data == '\r' ||
		    (*data == ' ' && (data[1] == ' ' || data[1] == '\t')))
			break;
		data++;
	}

	if (*data == '\0')
		return;

	/* @UNSAFE: convert/pack the whitespace */
	dest = data; last_lwsp = FALSE;
	while (*data != '\0') {
		if (*data == '\t' || *data == ' ' ||
		    *data == '\r' || *data == '\n') {
			if (!last_lwsp) {
				*dest++ = ' ';
				last_lwsp = TRUE;
			}
		} else {
			*dest++ = *data;
			last_lwsp = FALSE;
		}
		data++;
	}
	*dest = '\0';

	data = buffer_get_modifiable_data(buf, NULL);
	buffer_set_used_size(buf, (size_t) (dest - data)+1);
}

static void remove_subj_trailers(buffer_t *buf, size_t start_pos,
				 bool *is_reply_or_forward_r)
{
	const char *data;
	size_t orig_size, size;

	/* subj-trailer    = "(fwd)" / WSP */
	data = buffer_get_data(buf, &orig_size);

	if (orig_size < 1) /* size includes trailing \0 */
		return;

	for (size = orig_size-1; size > start_pos; ) {
		if (data[size-1] == ' ')
			size--;
		else if (size >= 5 &&
			 memcmp(data + size - 5, "(FWD)", 5) == 0) {
			*is_reply_or_forward_r = TRUE;
			size -= 5;
		} else {
			break;
		}
	}

	if (size != orig_size-1) {
		buffer_set_used_size(buf, size);
		buffer_append_c(buf, '\0');
	}
}

static bool remove_blob(const char **datap)
{
	const char *data = *datap;

	if (*data != '[')
		return FALSE;

	data++;
	while (*data != '\0' && *data != '[' && *data != ']')
		data++;

	if (*data != ']')
		return FALSE;

	data++;
	if (*data == ' ')
		data++;

	*datap = data;
	return TRUE;
}

static bool remove_subj_leader(buffer_t *buf, size_t *start_pos,
			       bool *is_reply_or_forward_r)
{
	const char *data, *orig_data;
	bool ret = FALSE;

	/* subj-leader     = (*subj-blob subj-refwd) / WSP

	   subj-blob       = "[" *BLOBCHAR "]" *WSP
	   subj-refwd      = ("re" / ("fw" ["d"])) *WSP [subj-blob] ":"

	   BLOBCHAR        = %x01-5a / %x5c / %x5e-7f
	                   ; any CHAR except '[' and ']' */
	orig_data = buf->data;
	orig_data += *start_pos;
	data = orig_data;

	if (*data == ' ') {
		/* independent from checks below - always removed */
		data++; orig_data++;
		*start_pos += 1;
		ret = TRUE;
	}

	while (*data == '[') {
		if (!remove_blob(&data))
			return ret;
	}

	if (str_begins(data, "RE"))
		data += 2;
	else if (str_begins(data, "FWD"))
		data += 3;
	else if (str_begins(data, "FW"))
		data += 2;
	else
		return ret;

	if (*data == ' ')
		data++;

	if (*data == '[' && !remove_blob(&data))
		return ret;

	if (*data != ':')
		return ret;

	data++;
	*start_pos += (size_t)(data - orig_data);
	*is_reply_or_forward_r = TRUE;
	return TRUE;
}

static bool remove_blob_when_nonempty(buffer_t *buf, size_t *start_pos)
{
	const char *data, *orig_data;

	orig_data = buf->data;
	orig_data += *start_pos;
	data = orig_data;
	if (*data == '[' && remove_blob(&data) && *data != '\0') {
		*start_pos += (size_t)(data - orig_data);
		return TRUE;
	}

	return FALSE;
}

static bool remove_subj_fwd_hdr(buffer_t *buf, size_t *start_pos,
				bool *is_reply_or_forward_r)
{
	const char *data = buf->data;
	size_t size = buf->used;

	/* subj-fwd        = subj-fwd-hdr subject subj-fwd-trl
	   subj-fwd-hdr    = "[fwd:"
	   subj-fwd-trl    = "]" */

	if (!str_begins(data + *start_pos, "[FWD:"))
		return FALSE;

	if (data[size-2] != ']')
		return FALSE;

	*is_reply_or_forward_r = TRUE;

	buffer_set_used_size(buf, size-2);
	buffer_append_c(buf, '\0');

	*start_pos += 5;
	return TRUE;
}

const char *imap_get_base_subject_cased(pool_t pool, const char *subject,
					bool *is_reply_or_forward_r)
{
	buffer_t *buf;
	size_t start_pos, subject_len;
	bool found;

	*is_reply_or_forward_r = FALSE;

	subject_len = strlen(subject);
	buf = buffer_create_dynamic(pool, subject_len);

	/* (1) Convert any RFC 2047 encoded-words in the subject to
	   UTF-8.  Convert all tabs and continuations to space.
	   Convert all multiple spaces to a single space. */
	message_header_decode_utf8((const unsigned char *)subject, subject_len,
				   buf, uni_utf8_to_decomposed_titlecase);
	buffer_append_c(buf, '\0');

	pack_whitespace(buf);

	start_pos = 0;
	do {
		/* (2) Remove all trailing text of the subject that matches
		   the subj-trailer ABNF, repeat until no more matches are
		   possible. */
		remove_subj_trailers(buf, start_pos, is_reply_or_forward_r);

		do {
			/* (3) Remove all prefix text of the subject that
			   matches the subj-leader ABNF. */
			found = remove_subj_leader(buf, &start_pos,
						   is_reply_or_forward_r);

			/* (4) If there is prefix text of the subject that
			   matches the subj-blob ABNF, and removing that prefix
			   leaves a non-empty subj-base, then remove the prefix
			   text. */
			found = remove_blob_when_nonempty(buf, &start_pos) ||
				found;

			/* (5) Repeat (3) and (4) until no matches remain. */
		} while (found);

		/* (6) If the resulting text begins with the subj-fwd-hdr ABNF
		   and ends with the subj-fwd-trl ABNF, remove the
		   subj-fwd-hdr and subj-fwd-trl and repeat from step (2). */
	} while (remove_subj_fwd_hdr(buf, &start_pos, is_reply_or_forward_r));

	/* (7) The resulting text is the "base subject" used in the
	   SORT. */
	return (const char *)buf->data + start_pos;
}
