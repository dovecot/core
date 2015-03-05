#ifndef STATS_PARSER_H
#define STATS_PARSER_H

struct stats;

enum stats_parser_type {
	STATS_PARSER_TYPE_UINT,
	STATS_PARSER_TYPE_TIMEVAL
};

struct stats_parser_field {
	const char *name;
	unsigned int offset;
	unsigned int size;
	enum stats_parser_type type;
};

bool stats_parser_diff(const struct stats_parser_field *fields,
		       unsigned int fields_count,
		       const struct stats *stats1, const struct stats *stats2,
		       struct stats *diff_stats_r, const char **error_r);
void stats_parser_add(const struct stats_parser_field *fields,
		      unsigned int fields_count,
		      struct stats *dest, const struct stats *src);
void stats_parser_value(string_t *str,
			const struct stats_parser_field *field,
			const void *data);

#endif
