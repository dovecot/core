#ifndef MAIL_HTML2TEXT_H
#define MAIL_HTML2TEXT_H

enum mail_html2text_flags {
	MAIL_HTML2TEXT_FLAG_SKIP_QUOTED	= 0x01
};

struct mail_html2text *
mail_html2text_init(enum mail_html2text_flags flags);
void mail_html2text_more(struct mail_html2text *ht,
			 const unsigned char *data, size_t size,
			 buffer_t *output);
void mail_html2text_deinit(struct mail_html2text **ht);

static inline bool
mail_html2text_content_type_match(const char *content_type)
{
	return strcasecmp(content_type, "text/html") == 0 ||
		strcasecmp(content_type, "application/xhtml+xml") == 0;
}

#endif
