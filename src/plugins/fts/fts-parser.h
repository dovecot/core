#ifndef FTS_PARSER_H
#define FTS_PARSER_H

struct message_block;

struct fts_parser {
	struct fts_parser *(*try_init)(const char *content_type,
				       const char *content_disposition);
	void (*more)(struct fts_parser *parser, struct message_block *block);
	void (*deinit)(struct fts_parser *parser);
};

extern struct fts_parser fts_parser_html;

bool fts_parser_init(const char *content_type, const char *content_disposition,
		     struct fts_parser **parser_r);
void fts_parser_more(struct fts_parser *parser, struct message_block *block);
void fts_parser_deinit(struct fts_parser **parser);

#endif
