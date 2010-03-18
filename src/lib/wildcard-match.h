#ifndef WILDCARD_MATCH_H
#define WILDCARD_MATCH_H

/* Returns TRUE if mask matches data. mask can contain '*' and '?' wildcards. */
bool wildcard_match(const char *data, const char *mask);
/* Like wildcard_match(), but match ASCII characters case-insensitively. */
bool wildcard_match_icase(const char *data, const char *mask);

#endif
