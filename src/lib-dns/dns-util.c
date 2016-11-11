/* Copyright (c) 2010-2016 Dovecot authors, see the included COPYING file */
#include "lib.h"
#include "dns-util.h"

/**
  return first position from b->a of c or a if not found
 */
static inline
const char *strchr_ba(const char *a, const char *b, char c)
{
	for(;b>a && *b != c; b--);
	return b;
}

int dns_ncompare(const char *a, const char *b, size_t n)
{
	if (a == NULL && b == NULL) return 0;
	if (a == NULL && b != NULL) return 1;
	if (a != NULL && b == NULL) return -1;

	for(size_t i = 0; i < n &&
			  *a != '\0' &&
			  *b != '\0' &&
			  dns_tolower(*a) == dns_tolower(*b);
	    i++, a++, b++);

	return dns_tolower(*a) - dns_tolower(*b);
}

int dns_compare(const char *a, const char *b)
{
	return dns_ncompare(a, b, (size_t)-1);
}

int dns_compare_labels(const char *a, const char *b)
{
	if (a == NULL && b == NULL) return 0;
	if (a == NULL && b != NULL) return 1;
	if (a != NULL && b == NULL) return -1;

	const char *ptr_a = a + strlen(a);
	const char *ptr_b = b + strlen(b);
	const char *label_a = ptr_a, *label_b = ptr_b;
	int comp = 0;

	while(comp == 0 && ptr_a > a && ptr_b > b) {
		/* look for start of label, including dot */
		label_a = strchr_ba(a, ptr_a, '.');
		label_b = strchr_ba(b, ptr_b, '.');
		if (ptr_a - label_a != ptr_b - label_b)
			/* compare labels up to minimum length
			   but include \0 to make sure that we
			   don't consider alpha and alphabet
			   equal */
			return dns_ncompare(label_a, label_b,
					   I_MIN(ptr_a - label_a,
						 ptr_b - label_b)+1);
		comp = dns_ncompare(label_a, label_b, ptr_a -label_a);
		ptr_a = label_a - 1;
		ptr_b = label_b - 1;
	}

	return dns_tolower(*label_a) - dns_tolower(*label_b);
}

int dns_match_wildcard(const char *name, const char *mask)
{
	i_assert(name != NULL && mask != NULL);

	for(;*name != '\0' && *mask != '\0'; name++, mask++) {
		switch(*mask) {
		case '*':
			name = strchr(name, '.');
			if (name == NULL || mask[1] != '.') return -1;
			mask++;
			break;
		case '?':
			break;
		default:
			if (dns_tolower(*name) != dns_tolower(*mask)) return -1;
		}
	}
	if (*mask == '*') mask++;
	return dns_tolower(*name) == dns_tolower(*mask) ? 0 : -1;
}
