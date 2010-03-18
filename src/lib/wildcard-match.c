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
#include "wildcard-match.h"

#include <ctype.h>

#define WILDS '*'  /* matches 0 or more characters (including spaces) */
#define WILDQ '?'  /* matches ecactly one character */

#define NOMATCH 0
#define MATCH (match+sofar)

static int wildcard_match_int(const char *data, const char *mask, int icase)
{
  const char *ma = mask, *na = data, *lsm = 0, *lsn = 0;
  int match = 1;
  int sofar = 0;

  /* null strings should never match */
  if ((ma == 0) || (na == 0) || (!*ma) || (!*na))
    return NOMATCH;
  /* find the end of each string */
  while (*(++mask));
  mask--;
  while (*(++data));
  data--;

  while (data >= na) {
    /* If the mask runs out of chars before the string, fall back on
     * a wildcard or fail. */
    if (mask < ma) {
      if (lsm) {
        data = --lsn;
        mask = lsm;
        if (data < na)
          lsm = 0;
        sofar = 0;
      }
      else
        return NOMATCH;
    }

    switch (*mask) {
    case WILDS:                /* Matches anything */
      do
        mask--;                    /* Zap redundant wilds */
      while ((mask >= ma) && (*mask == WILDS));
      lsm = mask;
      lsn = data;
      match += sofar;
      sofar = 0;                /* Update fallback pos */
      if (mask < ma)
        return MATCH;
      continue;                 /* Next char, please */
    case WILDQ:
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
    if (lsm) {                  /* To to fallback on '*' */
      data = --lsn;
      mask = lsm;
      if (data < na)
        lsm = 0;                /* Rewind to saved pos */
      sofar = 0;
      continue;                 /* Next char, please */
    }
    return NOMATCH;             /* No fallback=No match */
  }
  while ((mask >= ma) && (*mask == WILDS))
    mask--;                        /* Zap leftover %s & *s */
  return (mask >= ma) ? NOMATCH : MATCH;   /* Start of both = match */
}

bool wildcard_match(const char *data, const char *mask)
{
	return wildcard_match_int(data, mask, FALSE) != 0;
}

bool wildcard_match_icase(const char *data, const char *mask)
{
	return wildcard_match_int(data, mask, TRUE) != 0;
}
