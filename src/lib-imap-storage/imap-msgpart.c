#include "lib.h"
#include "array.h"
#include "istream.h"
#include "istream-crlf.h"
#include "istream-header-filter.h"
#include "message-parser.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "imap-parser.h"
#include "imap-msgpart.h"

int imap_msgpart_find(struct mail *mail, const char *section,
		      const struct message_part **part_r,
		      const char **subsection_r)
{
	struct message_part *part;
	const char *path;
	unsigned int num;

	if (mail_get_parts(mail, &part) < 0)
		return -1;

	path = section;
	while (*path >= '0' && *path <= '9' && part != NULL) {
		/* get part number, we have already verified its validity */
		num = 0;
		while (*path != '\0' && *path != '.') {
			i_assert(*path >= '0' && *path <= '9');

			num = num*10 + (*path - '0');
			path++;
		}

		if (*path == '.')
			path++;

		if ((part->flags & MESSAGE_PART_FLAG_MULTIPART) != 0) {
			/* find the part */
			part = part->children;
			for (; num > 1 && part != NULL; num--)
				part = part->next;
		} else {
			/* only 1 allowed with non-multipart messages */
			if (num != 1)
				part = NULL;
		}

		if (part != NULL &&
		    (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) != 0 &&
		    (*path >= '0' && *path <= '9')) {
			/* if we continue inside the message/rfc822, skip this
			   body part */
			part = part->children;
		}
	}

	*part_r = part;
	*subsection_r = path;
	return 0;
}

static bool
imap_msgpart_get_header_fields(const char *header_list,
			       const char *const **fields_r, size_t *count_r)
{
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args, *hdr_list;
	unsigned int list_count;
	ARRAY_TYPE(const_string) fields = ARRAY_INIT;
	unsigned int i;
	bool result = TRUE;

	input = i_stream_create_from_data(header_list, strlen(header_list));
	parser = imap_parser_create(input, NULL, (size_t)-1);

	if (imap_parser_finish_line(parser, 0, 0, &args) > 0 &&
	    imap_arg_get_list_full(args, &hdr_list, &list_count) &&
	    list_count > 0) {
		const char *value;
		
		if (fields_r != NULL)
			t_array_init(&fields, list_count);

		for (i = 0; i < list_count; i++) {
			if (!imap_arg_get_astring(&hdr_list[i], &value)) {
				result = FALSE;
				break;
			}

			if (fields_r != NULL) {
				value = t_str_ucase(value);
				array_append(&fields, &value, 1);
			}
		}

		if (fields_r != NULL) {
			*fields_r = array_get(&fields, &list_count);
			*count_r = list_count;
		}
	} else {
		result = FALSE;
	}

	imap_parser_unref(&parser);
	i_stream_unref(&input);

	return result;
}

static bool
imap_msgpart_verify_header_fields(const char *header_list, const char **error_r)
{
	/* HEADER.FIELDS (list), HEADER.FIELDS.NOT (list) */
	if (!imap_msgpart_get_header_fields(header_list, NULL, NULL)) {
		*error_r = "Invalid header fields";
		return FALSE;
	}
	return TRUE;
}

static struct istream *
imap_msgpart_get_partial_header(struct istream *mail_input, bool exclude,
				const char *header_list,
				struct message_size *hdr_size_r,
				const char **error_r)
{
	const char *const *hdr_fields;
	size_t hdr_count;
	struct istream *input;
	uoff_t old_offset;

	/* HEADER.FIELDS (list), HEADER.FIELDS.NOT (list) */
	if (!imap_msgpart_get_header_fields(header_list, &hdr_fields, &hdr_count)) {
		*error_r = "Invalid header fields";
		return NULL;
	}

	if (!exclude) {
		input = i_stream_create_header_filter(mail_input,
						      HEADER_FILTER_INCLUDE,
						      hdr_fields, hdr_count,
						      null_header_filter_callback, NULL);
	} else {
		input = i_stream_create_header_filter(mail_input,
						      HEADER_FILTER_EXCLUDE,
						      hdr_fields, hdr_count,
						      null_header_filter_callback, NULL);
	}

	old_offset = input->v_offset;
	if (message_get_header_size(input, hdr_size_r, NULL) < 0) {
		*error_r = "Failed to determine header size";
		return NULL;
	}
	i_stream_seek(input, old_offset);

	return input;
}

static bool
imap_msgpart_get_partial(struct istream *input, struct message_size part_size,
			 uoff_t partial_offset, uoff_t partial_size,
			 struct istream **stream_r, uoff_t *size_r)
{
	struct istream *result;
	uoff_t size = part_size.virtual_size;

	if (partial_offset >= size) {
		i_stream_unref(&input);
		*size_r = 0;
		*stream_r = NULL;
		return TRUE;
	}

	if (size != part_size.physical_size) {
		result = i_stream_create_crlf(input);
		i_stream_unref(&input);
		input = result;
	}

	if (partial_offset > 0)
		i_stream_seek(input, input->v_offset + partial_offset);

	size = partial_size > 0 && (size - partial_offset) > partial_size ?
		partial_size : (size - partial_offset);
	result = i_stream_create_limit(input, size);
	i_stream_unref(&input);
	
	*size_r = size;
	*stream_r = result;
	return TRUE;
}

bool imap_msgpart_open(struct mail *mail, const char *section,
		       uoff_t partial_offset, uoff_t partial_size,
		       struct istream **stream_r,
		       uoff_t *size_r, const char **error_r)
{
	struct message_size hdr_size, body_size, part_size;
	struct istream *input = NULL;

	/* only get stream when we intend to read actual data */
	if (stream_r != NULL) {
		if (mail_get_stream(mail, &hdr_size, &body_size, &input) < 0) {
			*error_r = "Failed to read message";
			return FALSE;
		}
	}

	if (section == NULL || *section == '\0') {
		/* full message */
		if (stream_r == NULL)
			return TRUE;

		part_size.physical_size =
			hdr_size.physical_size + body_size.physical_size;
		part_size.virtual_size =
			hdr_size.virtual_size + body_size.virtual_size;

		i_stream_seek(input, 0);
		i_stream_ref(input);
		return imap_msgpart_get_partial(input, part_size,
						partial_offset, partial_size,
						stream_r, size_r);
	}

	section = t_str_ucase(section);

	if (strcmp(section, "TEXT") == 0) {
		/* message body */
		if (stream_r == NULL)
			return TRUE;
		
		i_stream_seek(input, hdr_size.physical_size);
		i_stream_ref(input);
		return imap_msgpart_get_partial(input, body_size,
						partial_offset, partial_size,
						stream_r, size_r);
	}

	if (strncmp(section, "HEADER", 6) == 0) {
		/* header */
		if (stream_r == NULL) {
			if (section[6] == '\0') {
				return TRUE;
			} else if (strncmp(section, "HEADER.FIELDS ", 14) == 0) {
				return imap_msgpart_verify_header_fields(section+14, error_r);
			} else if (strncmp(section, "HEADER.FIELDS.NOT ", 18) == 0) {
				return imap_msgpart_verify_header_fields(section+18, error_r);
			}
		} else {
			i_stream_seek(input, 0);

			if (section[6] == '\0') {
				i_stream_ref(input);
			} else if (strncmp(section, "HEADER.FIELDS ", 14) == 0) {
				input = imap_msgpart_get_partial_header(input,
					FALSE, section+14, &hdr_size, error_r);
			} else if (strncmp(section, "HEADER.FIELDS.NOT ", 18) == 0) {
				input = imap_msgpart_get_partial_header(input,
					TRUE, section+18, &hdr_size, error_r);
			} else {
				input = NULL;
			}

			if (input != NULL) {
				return imap_msgpart_get_partial(input,
					hdr_size, partial_offset, partial_size,
					stream_r, size_r);
			}
		}

	} else if (*section >= '0' && *section <= '9') {
		const struct message_part *part;
		const char *subsection;

		if (imap_msgpart_find(mail, section, &part, &subsection) < 0) {
			*error_r = "Cannot read message part";
			return FALSE;
		}

		if (part == NULL) {
			*error_r = "Unknown message part";
			return FALSE;
		}

		if (*subsection == '\0') {
			if (stream_r == NULL)
				return TRUE;
		
			/* fetch the whole section */
			i_stream_seek(input, part->physical_pos +
				      part->header_size.physical_size);
			i_stream_ref(input);
			return imap_msgpart_get_partial(input, part->body_size, partial_offset,
					partial_size, stream_r, size_r);
		}

		if (strcmp(subsection, "MIME") == 0) {
			if (stream_r == NULL)
				return TRUE;

			/* fetch section's MIME header */
			i_stream_seek(input, part->physical_pos);
			i_stream_ref(input);
			return imap_msgpart_get_partial(input, part->header_size,
				partial_offset, partial_size, stream_r, size_r);
		}

		/* TEXT and HEADER are only for message/rfc822 parts */
		if ((part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) == 0) {
			*error_r = "Invalid section";
			return FALSE;
		}

		i_assert(part->children != NULL && part->children->next == NULL);
		part = part->children;

		if (strcmp(subsection, "TEXT") == 0) {
			if (stream_r == NULL)
				return TRUE;

			/* sub-message body */
			i_stream_seek(input, part->physical_pos +
				      part->header_size.physical_size);
			i_stream_ref(input);
			return imap_msgpart_get_partial(input, part->body_size,
				partial_offset, partial_size, stream_r, size_r);
		}	

		if (strncmp(subsection, "HEADER", 6) == 0) {
			if (stream_r == NULL) {
				if (section[6] == '\0') {
					return TRUE;
				} else if (strncmp(subsection, "HEADER.FIELDS ", 14) == 0) {
					return imap_msgpart_verify_header_fields(subsection+14, error_r);
				} else if (strncmp(subsection, "HEADER.FIELDS.NOT ", 18) == 0) {
					return imap_msgpart_verify_header_fields(subsection+18, error_r);
				}
			} else {
				i_stream_seek(input, part->physical_pos);

				if (subsection[6] == '\0') {
					/* full */
					hdr_size = part->header_size;
					i_stream_ref(input);
				} else if (strncmp(subsection, "HEADER.FIELDS ", 14) == 0) {
					input = imap_msgpart_get_partial_header(
							input, FALSE, section+14,
							&hdr_size, error_r);
				} else if (strncmp(subsection, "HEADER.FIELDS.NOT ", 18) == 0) {
					input = imap_msgpart_get_partial_header(
							input, TRUE, section+18,
							&hdr_size, error_r);
				} else {
					input = NULL;
				}

				if (input != NULL) {
					return imap_msgpart_get_partial(input,
						hdr_size, partial_offset,
						partial_size, stream_r, size_r);
				}
			}
		}
	}

	*error_r = "Invalid section";
	return FALSE;
}
