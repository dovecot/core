#ifndef FTS_PARSER_H
#define FTS_PARSER_H

struct message_block;
struct mail_user;

struct fts_parser_context {
	/* Can't be NULL */
	struct mail_user *user;
	/* Can't be NULL */
	const char *content_type;
	const char *content_disposition;
};

struct fts_parser_vfuncs {
	struct fts_parser *(*try_init)(struct fts_parser_context *parser_context);
	void (*more)(struct fts_parser *parser, struct message_block *block);
	int (*deinit)(struct fts_parser *parser, const char **retriable_err_msg_r);
	void (*unload)(void);
};

struct fts_parser {
	struct fts_parser_vfuncs v;
	buffer_t *utf8_output;
	bool may_need_retry;
	char *retriable_error_msg;
};

extern struct fts_parser_vfuncs fts_parser_html;
extern struct fts_parser_vfuncs fts_parser_script;
extern struct fts_parser_vfuncs fts_parser_tika;

bool fts_parser_init(struct fts_parser_context *parser_context,
		     struct fts_parser **parser_r);
struct fts_parser *fts_parser_text_init(void);

/* The parser is initially called with message body blocks. Once message is
   finished, it's still called with incoming size=0 while the parser increases
   it to non-zero. */
void fts_parser_more(struct fts_parser *parser, struct message_block *block);
int fts_parser_deinit(struct fts_parser **parser, const char **retriable_err_msg_r);

void fts_parsers_unload(void);

#endif
