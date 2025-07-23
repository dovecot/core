#ifndef DREGEX_H
#define DREGEX_H 1

enum dregex_flags {
	/* Match only at the first position */
	DREGEX_ANCHORED = BIT(0),
	/* Do not create automatic capture groups */
	DREGEX_NOSUB = BIT(1),
	/* Case insensitive matching */
	DREGEX_ICASE = BIT(2),
	/*  ^ and $ match newlines within data */
	DREGEX_NEWLINE = BIT(3),
	/* Subject string is not the beginning of a line */
	DREGEX_NOTBOL = BIT(4),
	/* Subject string is not the end of a line */
	DREGEX_NOTEOL = BIT(5),
	/* Reject non-ascii strings */
	DREGEX_ASCII_ONLY = BIT(6),
	/* Extended regular expression, skip whitespace and ignore comments,
	 * see https://www.pcre.org/current/doc/html/pcre2api.html */
	DREGEX_EXTENDED = BIT(7),
	/* Skip empty match groups */
	DREGEX_NO_EMPTY_SUB = BIT(8),

	/* Perform global replace */
	DREGEX_REPLACE_ALL = BIT(9),
	/* Replacement string is literal */
	DREGEX_REPLACE_LITERAL = BIT(10),
};

struct dregex_params {
	unsigned int max_cpu_seconds; /* maximum execution time, 1s default */
	unsigned int max_capture_groups; /* maximum number of capture groups, 100 default */
	unsigned int max_depth; /* maximum stack depth, 100 default */
};

/* Matches the given regular expression pattern against the subject string.
 *
 * Both pattern and subject are converted to UCS4 internally, making this UTF-8 safe.
 *
 * Returns:
 *  - -1 on error (with error_r optionally set to an error message)
 *  -  0 if the pattern does not match
 *  -  1 if the pattern matches
 */
int dregex_match(const char *pattern, const char *subject, enum dregex_flags flags,
		 const char **error_r);

int dregex_match_groups(const char *pattern, const char *subject, enum dregex_flags flags,
			ARRAY_TYPE(const_string) *groups_r, const char **error_r);

/* Performs a regular expression-based substitution on the subject string.
 * Replaces matches of 'pattern' with 'replace' and stores the result in *result_r.
 *
 * Both pattern, subject and replace are converted to UCS4 internally, making this UTF-8 safe.
 * Result will be allocated from the datastack pool.
 *
 * Returns:
 *  - -1 on error (with error_r optionally set to an error message)
 *  -  0 if no substitution was performed (no match)
 *  -  1 if substitution was successful
 */
int dregex_replace(const char *pattern, const char *subject, const char *replace,
		   string_t *result_r, enum dregex_flags flags,
		   const char **error_r);

struct dregex_code;

/* Creates a new regular expression context. This context
 * can be reused by calling code_compile again, which will
 * clear the old pattern.
*/
struct dregex_code *dregex_code_create(void);
struct dregex_code *dregex_code_create_params(const struct dregex_params *params);

/* Frees the regular expression context. */
void dregex_code_free(struct dregex_code **_code);

/* Compiles the given pattern into reusable code.
 *
 * Pattern is converted to UCS4 internally, making this UTF-8 safe.
 */
int dregex_code_compile(struct dregex_code *code, const char *pattern,
			enum dregex_flags flags, const char **error_r);

/* Exports the compiled pattern into the given buffer. */
void dregex_code_export(const struct dregex_code *code, buffer_t *buffer);

/* Imports a compiled pattern from the given buffer. */
int dregex_code_import(struct dregex_code *code, const buffer_t *buffer,
		       const char **error_r);

/* Executes regex matching with capture groups using precompiled code.
 * Same as dregex_match_groups().
 *
 * Subject is converted to UCS4 internally, making this UTF-8 safe.
 *
 * Groups are converted from UCS4 to UTF-8 internally.
 */
int dregex_code_match_groups(struct dregex_code *code, const char *subject,
			     ARRAY_TYPE(const_string) *groups_r, const char **error_r);

/* Executes regex matching using precompiled code.
 * Same as dregex_match().
 *
 * Subject is converted to UCS4 internally, making this UTF-8 safe.
 */
int dregex_code_match(struct dregex_code *code, const char *subject,
		      const char **error_r);

/* Performs regex replacement using precompiled code, starting at given offset.
 * Same as dregex_replace().
 *
 * Subject and replacement are converted to UCS4 internally, making this UTF-8 safe.
 * Result will be allocated from the datastack pool.
 */
int dregex_code_replace_full(struct dregex_code *code,
			     const char *subject, size_t startoffset,
			     const char *replacement,
			     string_t *result_r, enum dregex_flags flags,
			     const char **error_r);

/* Performs regex replacement using precompiled code.
 * Same as dregex_replace().
 *
 * Subject is converted to UCS4 internally, making this UTF-8 safe.
 * Result will be allocated from the datastack pool.
 */
int dregex_code_replace(struct dregex_code *code,
			const char *subject, const char *replacement,
			string_t *result_r, enum dregex_flags flags,
			const char **error_r);

#ifndef HAVE_LIBPCRE
#  define NO_DREGEX_SUPPORT "Missing regular expression support"
#  define NO_DREGEX_SUPPORT_CODE(error_r) \
	({STMT_START { *(error_r) = NO_DREGEX_SUPPORT;} STMT_END; -1;})
#  define dregex_match(pattern, subject, flags, error_r) NO_DREGEX_SUPPORT_CODE(error_r)
#  define dregex_match_groups(pattern, subject, flags, groups_r, error_r) \
	NO_DREGEX_SUPPORT_CODE(error_r)
#  define dregex_replace(pattern, subject, replace, result_r, \
			flags, error_r) NO_DREGEX_SUPPORT_CODE(error_r)
#  define dregex_code_create() ({ NULL; })
#  define dregex_code_free(code)
#  define dregex_code_compile(code, pattern, flags, error_r) NO_DREGEX_SUPPORT_CODE(error_r)
#  define dregex_code_export(code, buffer)
#  define dregex_code_import(code, buffer, error_r) NO_DREGEX_SUPPORT_CODE(error_r)
#  define dregex_code_match_groups(code, subject, groups_r, error_r) \
	NO_DREGEX_SUPPORT_CODE(error_r)
#  define dregex_code_match(code, subject, error_r) NO_DREGEX_SUPPORT_CODE(error_r)
#  define dregex_code_replace_full(code, subject, startoffset, replacement, result_r, \
				  flags, error_r) NO_DREGEX_SUPPORT_CODE(error_r)
#  define dregex_code_replace(code, subject, replacement, result_r, flags, error_r) \
	NO_DREGEX_SUPPORT_CODE(error_r)
#endif

#endif
