#ifndef MALLOC_OVERFLOW_H
#define MALLOC_OVERFLOW_H

/* MALLOC_*() can be used to calculate memory allocation sizes. If there's an
   overflow, it'll cleanly panic instead of causing a potential buffer
   overflow.

   Note that *_malloc(size+1) doesn't need to use MALLOC_ADD(size, 1). It wraps
   to size==0 and the *_malloc() calls already panic if size==0. */
static inline size_t
malloc_multiply_check(size_t a, size_t b, size_t sizeof_a, size_t sizeof_b,
		      const char *fname, unsigned int linenum)
{
	/* the first sizeof-checks are intended to optimize away this entire
	   if-check for types that are small enough to never wrap size_t. */
	if ((sizeof_a * 2 > sizeof(size_t) || sizeof_b * 2 > sizeof(size_t)) &&
	    b != 0 && (a > SIZE_MAX / b)) {
		i_panic("file %s: line %d: memory allocation overflow: %zu * %zu",
			fname, linenum, a, b);
	}
	return a * b;
}
#ifndef STATIC_CHECKER
#  define MALLOC_MULTIPLY(a, b) \
	malloc_multiply_check(a, b, sizeof(a), sizeof(b), __FILE__, __LINE__)
#else
/* avoid warning every time about sizeof(b) when b contains any arithmetic */
#  define MALLOC_MULTIPLY(a, b) \
	malloc_multiply_check(a, b, sizeof(a), sizeof(size_t), __FILE__, __LINE__)
#endif

static inline size_t
malloc_add_check(size_t a, size_t b, size_t sizeof_a, size_t sizeof_b,
		 const char *fname, unsigned int linenum)
{
	/* the first sizeof-checks are intended to optimize away this entire
	   if-check for types that are small enough to never wrap size_t. */
	if ((sizeof_a >= sizeof(size_t) || sizeof_b >= sizeof(size_t)) &&
	    SIZE_MAX - a < b) {
		i_panic("file %s: line %d: memory allocation overflow: %zu + %zu",
			fname, linenum, a, b);
	}
	return a + b;
}
#ifndef STATIC_CHECKER
#  define MALLOC_ADD(a, b) \
	malloc_add_check(a, b, sizeof(a), sizeof(b), __FILE__, __LINE__)
#else
/* avoid warning every time about sizeof(b) when b contains any arithmetic */
#  define MALLOC_ADD(a, b) \
	malloc_add_check(a, b, sizeof(a), sizeof(size_t), __FILE__, __LINE__)
#endif

#endif
