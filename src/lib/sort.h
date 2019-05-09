#ifndef SORT_H
#define SORT_H

#define INTEGER_CMP(name, type)					     \
	static inline int name(const type *i1, const type *i2)	     \
	{							     \
		if (*i1 < *i2)					     \
			return -1;				     \
		else if (*i1 > *i2)				     \
			return 1;				     \
		else						     \
			return 0;				     \
	}

INTEGER_CMP(uint64_cmp, uint64_t)
INTEGER_CMP(uint32_cmp, uint32_t)

#define i_qsort(base, nmemb, size, cmp) \
	qsort(base, nmemb, size -					\
	      CALLBACK_TYPECHECK(cmp, int (*)(typeof(const typeof(*base) *), \
					      typeof(const typeof(*base) *))), \
	      (int (*)(const void *, const void *))cmp)

#define i_bsearch(key, base, nmemb, size, cmp) \
	bsearch(key, base, nmemb, size - \
		CALLBACK_TYPECHECK(cmp, int (*)(typeof(const typeof(*key) *), \
						typeof(const typeof(*base) *))), \
		(int (*)(const void *, const void *))cmp)

int bsearch_strcmp(const char *key, const char *const *member) ATTR_PURE;
int bsearch_strcasecmp(const char *key, const char *const *member) ATTR_PURE;

#endif
