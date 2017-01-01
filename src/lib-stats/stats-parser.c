/* Copyright (c) 2011-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "time-util.h"
#include "stats-parser.h"

#define USECS_PER_SEC 1000000

static bool stats_diff_timeval(struct timeval *dest,
			       const struct timeval *src1,
			       const struct timeval *src2)
{
	long long diff_usecs;

	diff_usecs = timeval_diff_usecs(src2, src1);
	if (diff_usecs < 0)
		return FALSE;
	dest->tv_sec = diff_usecs / USECS_PER_SEC;
	dest->tv_usec = diff_usecs % USECS_PER_SEC;
	return TRUE;
}

static bool
stats_diff_uint32(uint32_t *dest, const uint32_t *src1, const uint32_t *src2)
{
	if (*src1 > *src2)
		return FALSE;
	*dest = *src2 - *src1;
	return TRUE;
}

static bool
stats_diff_uint64(uint64_t *dest, const uint64_t *src1, const uint64_t *src2)
{
	if (*src1 > *src2)
		return FALSE;
	*dest = *src2 - *src1;
	return TRUE;
}

bool stats_parser_diff(const struct stats_parser_field *fields,
		       unsigned int fields_count,
		       const struct stats *stats1, const struct stats *stats2,
		       struct stats *diff_stats_r, const char **error_r)
{
	unsigned int i;

	for (i = 0; i < fields_count; i++) {
		unsigned int offset = fields[i].offset;
		void *dest = PTR_OFFSET(diff_stats_r, offset);
		const void *src1 = CONST_PTR_OFFSET(stats1, offset);
		const void *src2 = CONST_PTR_OFFSET(stats2, offset);

		switch (fields[i].type) {
		case STATS_PARSER_TYPE_UINT:
			switch (fields[i].size) {
			case sizeof(uint32_t):
				if (!stats_diff_uint32(dest, src1, src2)) {
					*error_r = t_strdup_printf("%s %u < %u",
						fields[i].name,
						*(const uint32_t *)src2,
						*(const uint32_t *)src1);
					return FALSE;
				}
				break;
			case sizeof(uint64_t):
				if (!stats_diff_uint64(dest, src1, src2)) {
					const uint64_t *n1 = src1, *n2 = src2;

					*error_r = t_strdup_printf("%s %llu < %llu",
						fields[i].name,
						(unsigned long long)*n2,
						(unsigned long long)*n1);
					return FALSE;
				}
				break;
			default:
				i_unreached();
			}
			break;
		case STATS_PARSER_TYPE_TIMEVAL:
			if (!stats_diff_timeval(dest, src1, src2)) {
				const struct timeval *tv1 = src1, *tv2 = src2;

				*error_r = t_strdup_printf("%s %ld.%d < %ld.%d",
					fields[i].name,
					(long)tv2->tv_sec, (int)tv2->tv_usec,
					(long)tv1->tv_sec, (int)tv1->tv_usec);
				return FALSE;
			}
			break;
		}
	}
	return TRUE;
}

static void stats_timeval_add(struct timeval *dest, const struct timeval *src)
{
	dest->tv_sec += src->tv_sec;
	dest->tv_usec += src->tv_usec;
	if (dest->tv_usec > USECS_PER_SEC) {
		dest->tv_usec -= USECS_PER_SEC;
		dest->tv_sec++;
	}
}

void stats_parser_add(const struct stats_parser_field *fields,
		      unsigned int fields_count,
		      struct stats *dest, const struct stats *src)
{
	unsigned int i;

	for (i = 0; i < fields_count; i++) {
		unsigned int offset = fields[i].offset;
		void *f_dest = PTR_OFFSET(dest, offset);
		const void *f_src = CONST_PTR_OFFSET(src, offset);

		switch (fields[i].type) {
		case STATS_PARSER_TYPE_UINT:
			switch (fields[i].size) {
			case sizeof(uint32_t): {
				uint32_t *n_dest = f_dest;
				const uint32_t *n_src = f_src;

				*n_dest += *n_src;
				break;
			}
			case sizeof(uint64_t): {
				uint64_t *n_dest = f_dest;
				const uint64_t *n_src = f_src;

				*n_dest += *n_src;
				break;
			}
			default:
				i_unreached();
			}
			break;
		case STATS_PARSER_TYPE_TIMEVAL:
			stats_timeval_add(f_dest, f_src);
			break;
		}
	}
}

void stats_parser_value(string_t *str,
			const struct stats_parser_field *field,
			const void *data)
{
	const void *ptr = CONST_PTR_OFFSET(data, field->offset);

	switch (field->type) {
	case STATS_PARSER_TYPE_UINT:
		switch (field->size) {
		case sizeof(uint32_t): {
			const uint32_t *n = ptr;

			str_printfa(str, "%u", *n);
			break;
		}
		case sizeof(uint64_t): {
			const uint64_t *n = ptr;

			str_printfa(str, "%llu", (unsigned long long)*n);
			break;
		}
		default:
			i_unreached();
		}
		break;
	case STATS_PARSER_TYPE_TIMEVAL: {
		const struct timeval *tv = ptr;

		str_printfa(str, "%lu.%u", (unsigned long)tv->tv_sec,
			    (unsigned int)tv->tv_usec);
		break;
	}
	}
}
