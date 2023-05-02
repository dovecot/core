/*
 * This code would not have been possible without the prior work and
 * suggestions of various sourced.  Special thanks to Robey for
 * all his time/help tracking down bugs and his ever-helpful advice.
 *
 * 04/09:  Fixed the "*\*" against "*a" bug (caused an endless loop)
 *
 *   Chris Fuller  (aka Fred1@IRC & Fwitz@IRC)
 *     crf@cfox.bchs.uh.edu
 *
 * I hereby release this code into the public domain
 *
 */

#include "lib.h"
#include "str.h"
#include "wildcard-match.h"

#include <ctype.h>

#define WILDS '*'  /* matches 0 or more characters (including spaces) */
#define WILDQ '?'  /* matches exactly one character */
#define WILDE '\\' /* escapes one wildcard */

#define NOMATCH 0
#define MATCH (match+sofar)

static bool is_escaped(const char *p, const char *start)
{
  bool is_escaped = FALSE;
  while (p > start && p[-1] == WILDE) {
    is_escaped = !is_escaped;
    p--;
  }
  return is_escaped;
}

static int
wildcard_match_int(const char *data, const char *mask, bool icase, bool escaped)
{
  const char *ma = mask, *na = data, *lsm = NULL, *lsn = NULL;
  int match = 1;
  int sofar = 0;

  if (na[0] == '\0') {
	  /* empty string can match only "*" wildcard(s) */
	  while (ma[0] == '*') ma++;
	  return ma[0] == '\0' ? MATCH : NOMATCH;
  }
  /* find the end of each string */
  while (*(mask++) != '\0');
  mask-=2;
  while (*(data++) != '\0');
  data-=2;

  while (data >= na) {
    /* If the mask runs out of chars before the string, fall back on
     * a wildcard or fail. */
    if (mask < ma) {
      if (lsm != NULL) {
        data = --lsn;
        mask = lsm;
        if (data < na)
          lsm = NULL;
        sofar = 0;
      }
      else
        return NOMATCH;
    }

    switch (*mask) {
    case WILDE:
      if (escaped && is_escaped(mask, ma)) {
	if (*mask != *data)
	  goto nomatch;
	mask -= 2;
	data--;
	sofar++;
	continue;
      }
      break;
    case WILDS:                /* Matches anything */
      if (escaped && is_escaped(mask, ma)) {
	if (*mask != *data)
	  goto nomatch;
	mask -= 2;
	data--;
	sofar++;
	continue;
      }
      do
	mask--;                    /* Zap redundant wilds */
      while ((mask >= ma) && (*mask == WILDS) &&
	     (!escaped || !is_escaped(mask, ma)));
      lsm = mask;
      lsn = data;
      match += sofar;
      sofar = 0;                /* Update fallback pos */
      if (mask < ma)
	return MATCH;
      continue;                 /* Next char, please */
    case WILDQ:
      if (escaped && is_escaped(mask, ma)) {
	if (*mask != *data)
	  goto nomatch;
	mask -= 2;
	data--;
	sofar++;
	continue;
      }
      mask--;
      data--;
      continue;                 /* '?' always matches */
    }
    if (icase ? (i_toupper(*mask) == i_toupper(*data)) :
	(*mask == *data)) {     /* If matching char */
      mask--;
      data--;
      sofar++;                  /* Tally the match */
      continue;                 /* Next char, please */
    }
nomatch:
    if (lsm != NULL) {          /* To to fallback on '*' */
      data = --lsn;
      mask = lsm;
      if (data < na)
        lsm = NULL;                /* Rewind to saved pos */
      sofar = 0;
      continue;                 /* Next char, please */
    }
    return NOMATCH;             /* No fallback=No match */
  }
  while ((mask >= ma) && (*mask == WILDS) &&
	 (!escaped || !is_escaped(mask, ma)))
    mask--;                        /* Zap leftover %s & *s */
  return (mask >= ma) ? NOMATCH : MATCH;   /* Start of both = match */
}

bool wildcard_match(const char *data, const char *mask)
{
	return wildcard_match_int(data, mask, FALSE, FALSE) != 0;
}

bool wildcard_match_icase(const char *data, const char *mask)
{
	return wildcard_match_int(data, mask, TRUE, FALSE) != 0;
}

bool wildcard_match_escaped(const char *data, const char *mask)
{
	return wildcard_match_int(data, mask, FALSE, TRUE) != 0;
}

bool wildcard_match_escaped_icase(const char *data, const char *mask)
{
	return wildcard_match_int(data, mask, TRUE, TRUE) != 0;
}

bool wildcard_is_escaped_literal(const char *mask)
{
	const char *p = mask;

	while ((p = strpbrk(p, "*?\\")) != NULL) {
		if (*p != '\\')
			return FALSE;
		if (p[1] == '\0')
			break;
		p += 2;
	}
	return TRUE;
}

const char *wildcard_str_escape(const char *str)
{
	const char *p = strpbrk(str, "*?\\\"'");
	if (p == NULL)
		return str;

	string_t *esc = t_str_new((p - str) + strlen(p) + 8);
	do {
		str_append_data(esc, str, p - str);
		str_append_c(esc, '\\');
		str_append_c(esc, *p);

		str = p + 1;
		p = strpbrk(str, "*?\\\"'");
	} while (p != NULL);
	str_append(esc, str);
	return str_c(esc);
}
