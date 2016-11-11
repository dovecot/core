#ifndef DNS_UTIL_H
#define DNS_UTIL_H 1

static inline char
dns_tolower(char c)
{
	if (c >= 'A' && c <= 'Z')
		c+='a'-'A';
	return c;
}

/**
 * Will compare names in accordance with RFC4343
 */
int dns_compare(const char *a, const char *b) ATTR_PURE;
int dns_ncompare(const char *a, const char *b, size_t n) ATTR_PURE;

/**
 * Same as above but done by labels from right to left
 *
 * www.example.org and www.example.net would be compared as
 * org = net (return first difference)
 * example = example
 * www = www
 */
int dns_compare_labels(const char *a, const char *b) ATTR_PURE;

/**
 * Will match names in RFC4592 style
 *
 * this means *.foo.bar will match name.foo.bar
 * but *DOES NOT* match something.name.foo.bar
 */
int dns_match_wildcard(const char *name, const char *mask) ATTR_PURE;

#endif
