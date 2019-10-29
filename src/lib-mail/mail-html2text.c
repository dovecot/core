/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "unichar.h"
#include "message-parser.h"
#include "mail-html2text.h"

/* Zero-width space (&#x200B;) apparently also belongs here, but that gets a
   bit tricky to handle.. is it actually used anywhere? */
#define HTML_WHITESPACE(c) \
	((c) == ' ' || (c) == '\t' || (c) == '\r' || (c) == '\n')

enum html_state {
	/* regular text */
	HTML_STATE_TEXT,
	/* tag outside "quoted string" */
	HTML_STATE_TAG,
	/* tag inside "double quoted string" */
	HTML_STATE_TAG_DQUOTED,
	/* tag -> "escape\ */
	HTML_STATE_TAG_DQUOTED_ESCAPE,
	/* tag inside 'single quoted string' */
	HTML_STATE_TAG_SQUOTED,
	/* tag -> 'escape\ */
	HTML_STATE_TAG_SQUOTED_ESCAPE,
	/* comment */
	HTML_STATE_COMMENT,
	/* comment is ending, we've seen "--" and now just waiting for ">" */
	HTML_STATE_COMMENT_END,
	/* (java)script */
	HTML_STATE_SCRIPT,
	/* CSS style */
	HTML_STATE_STYLE,
	/* <![CDATA[...]]> */
	HTML_STATE_CDATA
};

struct mail_html2text {
	enum mail_html2text_flags flags;
	enum html_state state;
	buffer_t *input;
	unsigned int quote_level;
	bool ignore_next_text;
};

static struct {
	const char *name;
	unichar_t chr;
} html_entities[] = {
#include "html-entities.h"
};

struct mail_html2text *
mail_html2text_init(enum mail_html2text_flags flags)
{
	struct mail_html2text *ht;

	ht = i_new(struct mail_html2text, 1);
	ht->flags = flags;
	ht->input = buffer_create_dynamic(default_pool, 512);
	return ht;
}

static size_t
parse_tag_name(struct mail_html2text *ht,
	       const unsigned char *data, size_t size)
{
	size_t i;

	if (size >= 3 && memcmp(data, "!--", 3) == 0) {
		ht->state = HTML_STATE_COMMENT;
		return 3 + 1;
	}
	if (size >= 7 && i_memcasecmp(data, "script", 6) == 0 &&
	    (HTML_WHITESPACE(data[6]) || data[6] == '>')) {
		ht->state = HTML_STATE_SCRIPT;
		return 7 + 1;
	}
	if (size >= 6 && i_memcasecmp(data, "style", 5) == 0 &&
	    (HTML_WHITESPACE(data[5]) || data[5] == '>')) {
		ht->state = HTML_STATE_STYLE;
		return 6 + 1;
	}
	if (size >= 8 && i_memcasecmp(data, "![CDATA[", 8) == 0) {
		ht->state = HTML_STATE_CDATA;
		return 8 + 1;
	}

	if ((ht->flags & MAIL_HTML2TEXT_FLAG_SKIP_QUOTED) != 0) {
		if (size >= 10 && i_memcasecmp(data, "blockquote", 10) == 0 &&
		    (HTML_WHITESPACE(data[10]) || data[10] == '>')) {
			ht->quote_level++;
			ht->state = HTML_STATE_TAG;
			return 1;
		} else if (ht->quote_level > 0 &&
			   size >= 12 && i_memcasecmp(data, "/blockquote>", 12) == 0) {
			if (--ht->quote_level == 0)
				ht->ignore_next_text = FALSE;
			ht->state = HTML_STATE_TAG;
			return 1;
		}
	}
	if (size < 12) {
		/* can we see the whole tag name? */
		for (i = 0; i < size; i++) {
			if (HTML_WHITESPACE(data[i]) || data[i] == '>')
				break;
		}
		if (i == size) {
			/* need more data */
			return 0;
		}
	}
	ht->state = HTML_STATE_TAG;
	return 1;
}

static bool html_entity_get_unichar(const char *name, unichar_t *chr_r)
{
	unichar_t chr;

	for (size_t i = 0; i < N_ELEMENTS(html_entities); i++) {
		if (strcasecmp(html_entities[i].name, name) == 0) {
			*chr_r = html_entities[i].chr;
			return TRUE;
		}
	}

	/* maybe it's just encoded binary byte
	   it can be &#nnn; or &#xnnn;
	*/
	if (name[0] == '#' &&
	    ((name[1] == 'x' &&
	      str_to_uint32_hex(name+2, &chr) == 0) ||
	     str_to_uint32(name+1, &chr) == 0) &&
	     uni_is_valid_ucs4(chr)) {
		*chr_r = chr;
		return TRUE;
	}

	return FALSE;
}

static size_t parse_entity(const unsigned char *data, size_t size,
			   buffer_t *output)
{
	char entity[10];
	unichar_t chr;
	size_t i;

	for (i = 0; i < size; i++) {
		if (HTML_WHITESPACE(data[i]) || i >= sizeof(entity)) {
			/* broken entity */
			return 1;
		}
		if (data[i] == ';')
			break;
	}
	if (i == size)
		return 0;

	i_assert(i < sizeof(entity));
	memcpy(entity, data, i); entity[i] = '\0';

	if (html_entity_get_unichar(entity, &chr))
		uni_ucs4_to_utf8_c(chr, output);
	return i + 1 + 1;
}

static void mail_html2text_add_space(buffer_t *output)
{
	const unsigned char *data = output->data;

	if (output->used > 0 && data[output->used-1] != ' ' &&
	    data[output->used-1] != '\n')
		buffer_append_c(output, ' ');
}

static size_t
parse_data(struct mail_html2text *ht,
	   const unsigned char *data, size_t size, buffer_t *output)
{
	size_t i, ret;

	for (i = 0; i < size; i++) {
		char c = data[i];

		switch (ht->state) {
		case HTML_STATE_TEXT:
			if (c == '<') {
				ret = parse_tag_name(ht, data+i+1, size-i-1);
				if (ret == 0)
					return i;
				i += ret - 1;
			} else if (ht->quote_level == 0) {
				if (c == '&') {
					ret = parse_entity(data+i+1, size-i-1, output);
					if (ret == 0)
						return i;
					i += ret - 1;
				} else {
					buffer_append_c(output, c);
				}
			}
			break;
		case HTML_STATE_TAG:
			if (c == '"')
				ht->state = HTML_STATE_TAG_DQUOTED;
			else if (c == '\'')
				ht->state = HTML_STATE_TAG_SQUOTED;
			else if (c == '>') {
				ht->state = HTML_STATE_TEXT;
				mail_html2text_add_space(output);
			}
			break;
		case HTML_STATE_TAG_DQUOTED:
			if (c == '"')
				ht->state = HTML_STATE_TAG;
			else if (c == '\\')
				ht->state = HTML_STATE_TAG_DQUOTED_ESCAPE;
			break;
		case HTML_STATE_TAG_DQUOTED_ESCAPE:
			ht->state = HTML_STATE_TAG_DQUOTED;
			break;
		case HTML_STATE_TAG_SQUOTED:
			if (c == '\'')
				ht->state = HTML_STATE_TAG;
			else if (c == '\\')
				ht->state = HTML_STATE_TAG_SQUOTED_ESCAPE;
			break;
		case HTML_STATE_TAG_SQUOTED_ESCAPE:
			ht->state = HTML_STATE_TAG_SQUOTED;
			break;
		case HTML_STATE_COMMENT:
			if (c == '-') {
				if (i+1 == size)
					return i;
				if (data[i+1] == '-') {
					ht->state = HTML_STATE_COMMENT_END;
					i++;
				}
			}
			break;
		case HTML_STATE_COMMENT_END:
			if (c == '>')
				ht->state = HTML_STATE_TEXT;
			else if (!HTML_WHITESPACE(c))
				ht->state = HTML_STATE_COMMENT;
			break;
		case HTML_STATE_SCRIPT:
			if (c == '<') {
				unsigned int max_len = I_MIN(size-i, 9);

				if (i_memcasecmp(data+i, "</script>", max_len) == 0) {
					if (max_len < 9)
						return i;
					mail_html2text_add_space(output);
					ht->state = HTML_STATE_TEXT;
					i += 8;
				}
			}
			break;
		case HTML_STATE_STYLE:
			if (c == '<') {
				unsigned int max_len = I_MIN(size-i, 8);

				if (i_memcasecmp(data+i, "</style>", max_len) == 0) {
					if (max_len < 8)
						return i;
					mail_html2text_add_space(output);
					ht->state = HTML_STATE_TEXT;
					i += 7;
				}
			}
			break;
		case HTML_STATE_CDATA:
			if (c == ']') {
				unsigned int max_len = I_MIN(size-i, 3);

				if (i_memcasecmp(data+i, "]]>", max_len) == 0) {
					if (max_len < 3)
						return i;
					ht->state = HTML_STATE_TEXT;
					i += 2;
					break;
				}
			}
			if (ht->quote_level == 0)
				buffer_append_c(output, c);
			break;
		}
	}
	return i;
}

void mail_html2text_more(struct mail_html2text *ht,
			 const unsigned char *data, size_t size,
			 buffer_t *output)
{
	size_t pos, inc_size, buf_orig_size;

	i_assert(size > 0);

	while (ht->input->used > 0) {
		/* we didn't get enough input the last time to know
		   what to do. */
		buf_orig_size = ht->input->used;

		inc_size = I_MIN(size, 128);
		buffer_append(ht->input, data, inc_size);
		pos = parse_data(ht, ht->input->data,
				 ht->input->used, output);
		if (pos == 0) {
			/* we need to add more data into buffer */
			data += inc_size;
			size -= inc_size;
			if (size == 0)
				return;
		} else if (pos >= buf_orig_size) {
			/* we parsed forward */
			data += pos - buf_orig_size;
			size -= pos - buf_orig_size;
			buffer_set_used_size(ht->input, 0);
		} else {
			/* invalid input - eat away what we parsed so far
			   and retry */
			buffer_set_used_size(ht->input, buf_orig_size);
			buffer_delete(ht->input, 0, pos);
		}
	}
	pos = parse_data(ht, data, size, output);
	buffer_append(ht->input, data + pos, size - pos);
}

void mail_html2text_deinit(struct mail_html2text **_ht)
{
	struct mail_html2text *ht = *_ht;

	if (ht == NULL)
		return;

	*_ht = NULL;
	buffer_free(&ht->input);
	i_free(ht);
}
