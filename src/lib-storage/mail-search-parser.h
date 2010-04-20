#ifndef MAIL_SEARCH_PARSER_H
#define MAIL_SEARCH_PARSER_H

#define MAIL_SEARCH_PARSER_KEY_LIST "("

struct imap_arg;

/* Build a parser parsing the given imap args. NOTE: args must not be freed
   until this parser is destroyed. */
struct mail_search_parser *
mail_search_parser_init_imap(const struct imap_arg *args);
/* Build a parser parsing the given command line args. */
struct mail_search_parser *
mail_search_parser_init_cmdline(const char *const args[]);

void mail_search_parser_deinit(struct mail_search_parser **parser);

/* Key is set to the next search key, or MAIL_SEARCH_PARSER_KEY_LIST for
   beginning of a list. Returns 1 if ok, 0 if no more keys in this
   list/query, -1 if parsing error. */
int mail_search_parse_key(struct mail_search_parser *parser,
			  const char **key_r);
/* Get the next string. Returns 0 if ok, -1 if parsing error. */
int mail_search_parse_string(struct mail_search_parser *parser,
			     const char **value_r);
/* If next parameter equals to the given string case-insensitively, skip over
   it and return TRUE. Otherwise do nothing and return FALSE. */
bool mail_search_parse_skip_next(struct mail_search_parser *parser,
				 const char *str);

/* Returns the reason string for parsing error. */
const char *mail_search_parser_get_error(struct mail_search_parser *parser);

#endif
