/* Stripped down version of Cyrus imapd's glob.c
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Author: Chris Newman
 * Start Date: 4/5/93
 */
/*
 * $Id$
 */

#include "lib.h"
#include "imap-match.h"

#include <ctype.h>

struct _ImapMatchGlob {
    int inboxcase;
    const char *gstar, *ghier, *gptr;	/* INBOX prefix comparison state */
    char sep_char;		/* separator character */
    char inbox[6];		/* INBOX in the correct case */
    char str[1];		/* glob string */
};

/* name of "INBOX" -- must have no repeated substrings */
static char inbox[] = "INBOX";
#define INBOXLEN (sizeof (inbox) - 1)

/* initialize globbing structure
 *  This makes the following changes to the input string:
 *   1) '*' eats all '*'s and '%'s connected by any wildcard
 *   2) '%' eats all adjacent '%'s
 */
const ImapMatchGlob *imap_match_init(const char *str, int inboxcase,
				     char separator)
{
    ImapMatchGlob *g;
    char *dst;

    g = t_malloc(sizeof(ImapMatchGlob) + strlen(str) + 1);

    strcpy(g->inbox, inbox);
    g->sep_char = separator;
    dst = g->str;
    while (*str) {
	if (*str == '*' || *str == '%') {
	    /* remove duplicate hierarchy match (5) */
	    while (*str == '%') ++str;
	    /* If we found a '*', treat '%' as '*' (4) */
	    if (*str == '*') {
		/* remove duplicate wildcards (4) */
		while (*str == '*' || (*str == '%' && str[1])) ++str;
		*dst++ = '*';
	    } else {
		*dst++ = '%';
	    }
	} else {
	    *dst++ = *str++;
	}
    }
    *dst++ = '\0';

    /* pre-match "INBOX" to the pattern case insensitively and save state
     * also keep track of the matching case for "INBOX"
     * NOTE: this only works because "INBOX" has no repeated substrings
     */
    if (inboxcase) {
	g->inboxcase = TRUE,
	str = g->str;
	dst = g->inbox;
	g->gstar = g->ghier = NULL;
	do {
	    while (*dst && i_toupper(*str) == i_toupper(*dst)) {
		*dst++ = *str++;
	    }
	    if (*str == '*') g->gstar = ++str, g->ghier = 0;
	    else if (*str == '%') g->ghier = ++str;
	    else break;
	    if (*str != '%') {
		while (*dst && i_toupper(*str) != i_toupper(*dst)) ++dst;
	    }
	} while (*str && *dst);
	g->gptr = str;
	if (*dst) g->inboxcase = FALSE;
    }

    return (g);
}

/* returns -1 if no match, otherwise length of match or partial-match
 *  g         pre-processed glob string
 *  ptr       string to perform glob on
 *  len       length of ptr string
 *  min       pointer to minimum length of a valid partial-match
 *            set to return value + 1 on partial match, otherwise -1
 *            if NULL, partial matches not allowed
 */
int imap_match(const ImapMatchGlob *glob, const char *ptr,
	       int len, int *min)
{
    const char *gptr, *pend;	/* glob pointer, end of ptr string */
    const char *gstar, *pstar;	/* pointers for '*' patterns */
    const char *ghier, *phier;	/* pointers for '%' patterns */
    const char *start;		/* start of input string */

    /* check for remaining partial matches */
    if (min && *min < 0) return (-1);

    /* get length */
    if (!len) len = strlen(ptr);

    /* initialize globbing */
    gptr = glob->str;
    start = ptr;
    pend = ptr + len;
    gstar = ghier = NULL;
    phier = pstar = NULL;	/* initialize to eliminate warnings */

    /* check for INBOX prefix */
    if (glob->inboxcase && strncmp(ptr, inbox, INBOXLEN) == 0) {
	pstar = phier = ptr += INBOXLEN;
	gstar = glob->gstar;
	ghier = glob->ghier;
	gptr = glob->gptr;
    }

    /* main globbing loops */
    /* case sensitive version */

    /* loop to manage wildcards */
    do {
	/* see if we match to the next '%' or '*' wildcard */
	while (*gptr != '*' && *gptr != '%' && ptr != pend && *gptr == *ptr) {
	    ++ptr, ++gptr;
	}
	if (*gptr == '\0' && ptr == pend) break;
	if (*gptr == '*') {
	    ghier = NULL;
	    gstar = ++gptr;
	    pstar = ptr;
	}
	if (*gptr == '%') {
	    ghier = ++gptr;
	    phier = ptr;
	}
	if (ghier) {
	    /* look for a match with first char following '%',
	     * stop at a sep_char unless we're doing "*%"
	     */
	    ptr = phier;
	    while (ptr != pend && *ghier != *ptr
		   && (*ptr != glob->sep_char ||
		       (!*ghier && gstar && *gstar == '%' && min
			&& ptr - start < *min))) {
		++ptr;
	    }
	    if (ptr == pend) {
		gptr = ghier;
		break;
	    }
	    if (*ptr == glob->sep_char && *ptr != *ghier) {
		if (!*ghier && min
		    && *min < ptr - start && ptr != pend
		    && *ptr == glob->sep_char
		    ) {
		    *min = gstar ? ptr - start + 1 : -1;
		    return (ptr - start);
		}
		gptr = ghier;
		ghier = NULL;
	    } else {
		phier = ++ptr;
		gptr = ghier + 1;
	    }
	}
	if (gstar && !ghier) {
	    if (!*gstar) {
		ptr = pend;
		break;
	    }
	    /* look for a match with first char following '*' */
	    while (pstar != pend && *gstar != *pstar) ++pstar;
	    if (pstar == pend) {
		gptr = gstar;
		break;
	    }
	    ptr = ++pstar;
	    gptr = gstar + 1;
	}
	if (*gptr == '\0' && min && *min < ptr - start && ptr != pend &&
	    *ptr == glob->sep_char) {
	    /* The pattern ended on a hierarchy separator
	     * return a partial match */
	    *min = ptr - start + 1;
	    return ptr - start;
	}

	/* continue if at wildcard or we passed an asterisk */
    } while (*gptr == '*' || *gptr == '%' ||
	     ((gstar || ghier) && (*gptr || ptr != pend)));

    if (min) *min = -1;
    return (*gptr == '\0' && ptr == pend ? ptr - start : -1);
}
