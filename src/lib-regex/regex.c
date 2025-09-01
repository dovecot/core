/* Copyright (C) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "cpu-limit.h"
#include "str.h"
#include "unichar.h"
#include "dregex.h"

#ifdef HAVE_LIBPCRE

#define PCRE2_CODE_UNIT_WIDTH 32
#include "pcre2.h"

#define DREGEX_MAX_DEPTH 100
#define DREGEX_MAX_MATCHES 100
#define DREGEX_MAX_CPU_SECONDS 1

struct dregex_code {
	pool_t pool;

	pcre2_compile_context *cctx;
	pcre2_general_context *gctx;
	pcre2_match_context *mctx;
	pcre2_code *pat;

	struct cpu_limit *climit;

	unsigned int max_depth;
	unsigned int max_cpu_seconds;
	unsigned int max_capture_groups;

	enum dregex_flags flags;
};

static void *dregex_code_int_malloc(size_t amt, void *_ctx)
{
	struct dregex_code *ctx = _ctx;
	return p_malloc(ctx->pool, amt);
}

static void dregex_code_int_free(void *ptr, void *_ctx)
{
	struct dregex_code *ctx = _ctx;
	p_free(ctx->pool, ptr);
}

static int dregex_code_callout(pcre2_callout_block *block ATTR_UNUSED, void *ctx)
{
	struct dregex_code *code = ctx;
	if (cpu_limit_exceeded(code->climit))
		return PCRE2_ERROR_PATTERN_TOO_COMPLICATED;
	return 0;
}

#ifdef HAVE_PCRE2_SUBSTITUTE_CALLOUT_BLOCK
static int
dregex_code_substitute_callout(pcre2_substitute_callout_block *block ATTR_UNUSED, void *ctx)
{
	return dregex_code_callout(NULL, ctx);
}
#endif

static int dregex_code_guard(uint depth, void *ctx)
{
	struct dregex_code *code = ctx;
	if (code->max_depth < depth)
		return PCRE2_ERROR_DEPTHLIMIT;
	return 0;
}

static void dregex_code_init(struct dregex_code *code)
{
	code->gctx = pcre2_general_context_create(dregex_code_int_malloc,
						  dregex_code_int_free, code);
	code->cctx = pcre2_compile_context_create(code->gctx);
	code->mctx = pcre2_match_context_create(code->gctx);

	pcre2_set_compile_recursion_guard(code->cctx, dregex_code_guard, code);
	/* these are used to ensure that CPU time isn't exceeded */
	pcre2_set_callout(code->mctx, dregex_code_callout, code);
#ifdef HAVE_PCRE2_SUBSTITUTE_CALLOUT_BLOCK
	pcre2_set_substitute_callout(code->mctx, dregex_code_substitute_callout, code);
#endif

	/* Set some limits */
	pcre2_set_match_limit(code->mctx, code->max_capture_groups);
	pcre2_set_depth_limit(code->mctx, code->max_depth);
}

struct dregex_code *dregex_code_create_params(const struct dregex_params *params)
{
	pool_t pool = pool_allocfree_create("regex pool");
	struct dregex_code *code = p_new(pool, struct dregex_code, 1);
	code->pool = pool;
	code->max_capture_groups = params->max_capture_groups;
	code->max_cpu_seconds = params->max_cpu_seconds;
	code->max_depth = params->max_depth;
	dregex_code_init(code);
	return code;
}

static const struct dregex_params default_params = {
	.max_depth = DREGEX_MAX_DEPTH,
	.max_cpu_seconds = DREGEX_MAX_CPU_SECONDS,
	.max_capture_groups = DREGEX_MAX_MATCHES,
};

struct dregex_code *dregex_code_create(void)
{
	struct dregex_code *code = dregex_code_create_params(&default_params);
	dregex_code_init(code);
	return code;
}

static const PCRE2_SPTR empty_str = U"";

/* Convert input into unichars */
static int convert_to_sptr(const char *input, PCRE2_SPTR *out_r, PCRE2_SIZE *len_r,
			   bool refuse_non_ascii)
{
	if (*input == '\0') {
		*len_r = 0;
		*out_r = empty_str;
	}
	ARRAY_TYPE(unichars) chars;
	t_array_init(&chars, 128);
	if (refuse_non_ascii) {
		/* treat everything as ascii */
		for (; *input != '\0'; input++) {
			unichar_t chr = (unsigned char)*input;
			array_push_back(&chars, &chr);
		}
	} else if (uni_utf8_to_ucs4(input, &chars) < 0)
		return -1;
	*len_r = array_count(&chars);
	if (*len_r == 0)
		*out_r = empty_str;
	else
		*out_r = array_idx(&chars, 0);
	return 0;
}

/* Handle error */
static int handle_error(int ret, const char *func, const char **error_r)
{
	PCRE2_UCHAR buf[256];
	if (ret == PCRE2_ERROR_NOMEMORY)
		i_fatal_status(FATAL_OUTOFMEM, "%s(): Out of memory", func);
	int rc = pcre2_get_error_message(ret, buf, sizeof(buf));
		/* Ignore, the error didn't fit to buffer */
	if (rc == PCRE2_ERROR_BADDATA) {
		*error_r = t_strdup_printf("Unknown error %d occured", ret);
	} else if (rc < 0) {
		*error_r = t_strdup_printf("Unknown error %d occured while handling %d",
					   rc, ret);
	} else {
		/* we are ignoring PCRE2_ERROR_NOMEMORY here because it
		 * likely means the output did not fit in 256 characters. */
		buffer_t *output = t_buffer_create(rc);
		uni_ucs4_to_utf8(buf, rc, output);
		*error_r = str_c(output);
	}
	return -1;
}
#define handle_error(ret, error_r) handle_error((ret), __func__, (error_r))

int dregex_code_compile(struct dregex_code *code, const char *pattern,
			enum dregex_flags flags, const char **error_r)
{
	i_assert(code != NULL);
	i_assert(pattern != NULL);
	int errcode;
	PCRE2_SIZE erroffset;

	if (code->pat != NULL) {
		pcre2_code_free(code->pat);
		code->pat = NULL;
		code->flags = 0;
	}

	uint options = PCRE2_AUTO_CALLOUT |
		PCRE2_NEVER_BACKSLASH_C | PCRE2_NO_UTF_CHECK;

	if (HAS_ALL_BITS(flags, DREGEX_ICASE))
		options |= PCRE2_CASELESS;
	if (HAS_ALL_BITS(flags, DREGEX_NOSUB))
		options |= PCRE2_NO_AUTO_CAPTURE;
	if (HAS_ALL_BITS(flags, DREGEX_NEWLINE))
		options |= PCRE2_MULTILINE;
	if (HAS_ALL_BITS(flags, DREGEX_ANCHORED))
		options |= PCRE2_ANCHORED;
	if (HAS_ALL_BITS(flags, DREGEX_EXTENDED))
		options |= PCRE2_EXTENDED;

	bool refuse_non_ascii = HAS_ALL_BITS(flags, DREGEX_ASCII_ONLY);
	code->flags = flags;

	/* Use Unicode properties for character matching */
	if (!refuse_non_ascii)
		options |= (PCRE2_UCP | PCRE2_UTF);
	else
		options |= PCRE2_NEVER_UTF;

	T_BEGIN {
		PCRE2_SIZE slen;
		PCRE2_SPTR32 pattern32;
		if (convert_to_sptr(pattern, &pattern32, &slen, refuse_non_ascii) < 0) {
			errcode = PCRE2_ERROR_BADDATA;
			code->pat = NULL;
		} else {
			code->pat = pcre2_compile(pattern32, slen, options, &errcode,
						  &erroffset, code->cctx);
		}
	} T_END;

	i_assert(code->pat != NULL || errcode != 0);

	if (code->pat == NULL)
		return handle_error(errcode, error_r);

	return 0;
}

void dregex_code_export(const struct dregex_code *code, buffer_t *buffer)
{
	PCRE2_SIZE size;
	uint8_t *bytes;

	const pcre2_code *codes[] = {
		code->pat,
	};

	int ret = pcre2_serialize_encode(codes, N_ELEMENTS(codes), &bytes,
					 &size, code->gctx);
	if (ret < 0) {
		const char *error;
		(void)handle_error(ret, &error);
		i_panic("BUG: dregex_code_export(): %s", error);
	}

	/* There must be only one pattern */
	i_assert(ret == 1);

	buffer_append(buffer, bytes, size);
	pcre2_serialize_free(bytes);
}

int dregex_code_import(struct dregex_code *code, const buffer_t *buffer,
		       const char **error_r)
{
	int ret = pcre2_serialize_decode(&code->pat, 1, buffer->data,
					 code->gctx);
	if (ret < 0)
		return handle_error(ret, error_r);
	i_assert(ret > 0);

	return 0;
}

static const char *empty_match_str = "";

static void extract_matches(uint count, pcre2_match_data *mdata,
			    bool skip_empty, ARRAY_TYPE(const_string) *groups_r)
{
	/* we don't actually want matches */
	if (groups_r == NULL)
		return;
	for (uint i = 0; i < count; i++) {
		PCRE2_UCHAR32 *buf;
		PCRE2_SIZE bsize;
		int rc = pcre2_substring_length_bynumber(mdata, i, &bsize);
		if (rc == PCRE2_ERROR_NOSUBSTRING)
			break;
		else if (rc == PCRE2_ERROR_UNSET) {
			if (!skip_empty)
				array_push_back(groups_r, &empty_match_str);
			continue;
		} else if (rc == PCRE2_ERROR_UNAVAILABLE)
			continue;
		pcre2_substring_get_bynumber(mdata, i, &buf, &bsize);
		buffer_t *output = t_buffer_create(bsize);
		uni_ucs4_to_utf8(buf, bsize, output);
		const char *substr = str_c(output);
		array_push_back(groups_r, &substr);
	}
}

static int dregex_code_match_int(struct dregex_code *code, const char *subject,
				 pcre2_match_data *mdata, const char **error_r)
{
	i_assert(code != NULL);
	i_assert(code->pat != NULL);
	i_assert(subject != NULL);

	PCRE2_SIZE slen;
	PCRE2_SPTR subject32;

	bool refuse_non_ascii = HAS_ALL_BITS(code->flags, DREGEX_ASCII_ONLY);
	if (convert_to_sptr(subject, &subject32, &slen, refuse_non_ascii) < 0)
		return handle_error(PCRE2_ERROR_BADDATA, error_r);

	/* Empty string is not a match */
	uint options = PCRE2_NOTEMPTY;

	if (HAS_ALL_BITS(code->flags, DREGEX_NOTBOL))
		options |= PCRE2_NOTBOL;
	if (HAS_ALL_BITS(code->flags, DREGEX_NOTEOL))
		options |= PCRE2_NOTEOL;
	if (HAS_ALL_BITS(code->flags, DREGEX_ANCHORED))
		options |= PCRE2_ANCHORED;

	code->climit = cpu_limit_init(code->max_cpu_seconds, CPU_LIMIT_TYPE_ALL);
	int ret = pcre2_match(code->pat, subject32, slen, 0, options,
			      mdata, code->mctx);
	cpu_limit_deinit(&code->climit);

	if (ret == PCRE2_ERROR_NOMATCH) {
		/* did not match */
		ret = 0;
	} else if (ret < 0) {
		return handle_error(ret, error_r);
	}

	return ret;
}

int dregex_code_match_groups(struct dregex_code *code, const char *subject,
			     ARRAY_TYPE(const_string) *groups_r, const char **error_r)
{
	i_assert(code != NULL);
	i_assert(code->pat != NULL);
	int ret;

	T_BEGIN {
		pcre2_match_data *mdata =
			pcre2_match_data_create_from_pattern(code->pat, code->gctx);
		ret = dregex_code_match_int(code, subject, mdata, error_r);
		if (ret > 1) {
			bool skip_empty = HAS_ALL_BITS(code->flags, DREGEX_NO_EMPTY_SUB);
			/* ret is number of groups */
			extract_matches((uint32_t)ret, mdata, skip_empty, groups_r);
			ret = 1;
		}
	} T_END_PASS_STR_IF(ret < 0, error_r);
	return ret;
}

int dregex_code_match(struct dregex_code *code, const char *subject,
		      const char **error_r)
{
	return dregex_code_match_groups(code, subject, NULL, error_r);
}

int dregex_code_replace_full(struct dregex_code *code,
			     const char *subject, size_t startoffset,
			     const char *replacement, string_t *result_r,
			     enum dregex_flags flags, const char **error_r)
{
	i_assert(code != NULL);
	i_assert(code->pat != NULL);
	i_assert(subject != NULL);
	i_assert(replacement != NULL);
	i_assert(result_r != NULL);

	uint options = PCRE2_NOTEMPTY;
	if (HAS_ALL_BITS(flags, PCRE2_ANCHORED))
		options |= PCRE2_ANCHORED;
	if (HAS_ALL_BITS(flags, DREGEX_REPLACE_ALL))
		options |= PCRE2_SUBSTITUTE_GLOBAL;
	if (HAS_ALL_BITS(flags, DREGEX_REPLACE_LITERAL)) {
#ifdef PCRE2_SUBSTITUTE_LITERAL
		options |= PCRE2_SUBSTITUTE_LITERAL;
#else
		*error_r = "DREGEX_REPLACE_LITERAL not supported on this platform";
		return -1;
#endif
	}

	PCRE2_UCHAR *result32 = U"";
	PCRE2_SIZE result_len = 0;

	int ret;
	bool refuse_non_ascii = HAS_ALL_BITS(flags, DREGEX_ASCII_ONLY) ||
				HAS_ALL_BITS(code->flags, DREGEX_ASCII_ONLY);

	T_BEGIN do {
		PCRE2_SIZE slen;
		PCRE2_SPTR subject32;
		PCRE2_SIZE rlen;
		PCRE2_SPTR replacement32;

		if (convert_to_sptr(subject, &subject32, &slen, refuse_non_ascii) < 0 ||
		    convert_to_sptr(replacement, &replacement32, &rlen, refuse_non_ascii) < 0) {
			ret = PCRE2_ERROR_BADDATA;
			break;
		}

		pcre2_match_data *mdata =
			pcre2_match_data_create_from_pattern(code->pat, code->gctx);

		code->climit = cpu_limit_init(code->max_cpu_seconds,
					      CPU_LIMIT_TYPE_ALL);
		ret = pcre2_substitute(code->pat, subject32, slen, startoffset,
				       options|PCRE2_SUBSTITUTE_OVERFLOW_LENGTH,
				       mdata, code->mctx, replacement32, rlen,
				       result32, &result_len);
		cpu_limit_deinit(&code->climit);
		/* Ignore NOMEMORY error here, it's because we asked how long
		   the result would be. */
		if (ret != PCRE2_ERROR_NOMEMORY && ret < 0) {
			pcre2_match_data_free(mdata);
			break;
		}

		if (result_len > 0)
			result32 = t_new(PCRE2_UCHAR, result_len);

		/* Run it again as we know the buffer size now */
		code->climit = cpu_limit_init(code->max_cpu_seconds,
					      CPU_LIMIT_TYPE_ALL);
		ret = pcre2_substitute(code->pat, subject32, slen, startoffset, options,
				       mdata, code->mctx, replacement32, rlen,
				       result32, &result_len);
		cpu_limit_deinit(&code->climit);
		pcre2_match_data_free(mdata);
	} while(0); T_END;

	if (ret < 0)
		return handle_error(ret, error_r);
	else if (ret > 0)
		uni_ucs4_to_utf8(result32, result_len, result_r);

	return ret > 0 ? 1 : 0;
}

int dregex_code_replace(struct dregex_code *code, const char *subject,
			const char *replacement, string_t *result_r,
			enum dregex_flags flags, const char **error_r)
{
	return dregex_code_replace_full(code, subject, 0, replacement, result_r,
					flags, error_r);
}

void dregex_code_free(struct dregex_code **_code)
{
	struct dregex_code *code = *_code;
	*_code = NULL;
	if (code == NULL)
		return;

	if (code->pat != NULL)
		pcre2_code_free(code->pat);
	pcre2_match_context_free(code->mctx);
	pcre2_compile_context_free(code->cctx);
	pcre2_general_context_free(code->gctx);
	pool_unref(&code->pool);
}

int dregex_match_groups(const char *pattern, const char *subject, enum dregex_flags flags,
			ARRAY_TYPE(const_string) *groups_r, const char **error_r)
{
	struct dregex_code *code = dregex_code_create();
	int ret;

	T_BEGIN {
		if (dregex_code_compile(code, pattern, flags, error_r) < 0)
			ret = -1;
		else {
			ret = dregex_code_match_groups(code, subject, groups_r,
						       error_r);
		}
	} T_END_PASS_STR_IF(ret < 0, error_r);
	dregex_code_free(&code);

	return ret;
}

int dregex_match(const char *pattern, const char *subject, enum dregex_flags flags,
		 const char **error_r)
{
	return dregex_match_groups(pattern, subject, flags, NULL, error_r);
}

int dregex_replace(const char *pattern, const char *subject, const char *replace,
		   string_t *result_r, enum dregex_flags flags,
		   const char **error_r)
{
	struct dregex_code *code = dregex_code_create();
	int ret;

	T_BEGIN {
		ret = dregex_code_compile(code, pattern, flags, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);

	if (ret >= 0) {
		ret = dregex_code_replace(code, subject, replace, result_r,
					  flags, error_r);
	}

	dregex_code_free(&code);

	return ret;
}

#endif
