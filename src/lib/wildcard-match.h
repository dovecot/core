#ifndef WILDCARD_MATCH_H
#define WILDCARD_MATCH_H

/* Returns TRUE if mask matches data. mask can contain '*' and '?' wildcards. */
bool wildcard_match(const char *data, const char *mask);
/* Like wildcard_match(), but match ASCII characters case-insensitively. */
bool wildcard_match_icase(const char *data, const char *mask);

/* Returns TRUE if mask does *not* contain any '*' or '?' wildcards. */
static inline bool wildcard_is_literal(const char *mask)
{
	return strpbrk(mask, "*?") == NULL;
}

bool wildcard_match_escaped(const char *data, const char *mask);
bool wildcard_match_escaped_icase(const char *data, const char *mask);
/* Returns TRUE if mask does *not* contain any '*' or '?' wildcards, except
   preceded by '\' escape character. */
bool wildcard_is_escaped_literal(const char *mask);

/* Same as str_escape(), but also escape '*' and '?' characters. */
const char *wildcard_str_escape(const char *str);

#endif
