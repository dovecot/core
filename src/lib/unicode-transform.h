#ifndef UNICODE_NF_H
#define UNICODE_NF_H

/*
 * Transform API
 */

struct unicode_transform;

struct unicode_transform_buffer {
	const uint32_t *cp;
	const struct unicode_code_point_data *const *cp_data;
	size_t cp_count;
};

struct unicode_transform_def {
	ssize_t (*input)(struct unicode_transform *trans,
			 const struct unicode_transform_buffer *buf,
			 const char **error_r);
	int (*flush)(struct unicode_transform *trans, bool finished,
		     const char **error_r);
};

struct unicode_transform {
	const struct unicode_transform_def *def;
	struct unicode_transform *next;
};

static inline void
unicode_transform_init(struct unicode_transform *trans,
		       const struct unicode_transform_def *def)
{
	i_zero(trans);
	trans->def = def;
}

static inline void
unicode_transform_chain(struct unicode_transform *trans,
			struct unicode_transform *next)
{
	i_assert(trans->next == NULL);
	trans->next = next;
}

static inline struct unicode_transform *
unicode_transform_get_last(struct unicode_transform *trans)
{
	while (trans->next != NULL)
		trans = trans->next;
	return trans;
}

ssize_t uniform_transform_forward(
	struct unicode_transform *trans, const uint32_t *out,
	const struct unicode_code_point_data *const *out_data, size_t out_len,
	const char **error_r);

ssize_t unicode_transform_input(struct unicode_transform *trans,
				const uint32_t *in, size_t in_len,
				const char **error_r);
int unicode_transform_flush(struct unicode_transform *trans,
			    const char **error_r);

/* Buffer Sink */

struct unicode_buffer_sink {
	struct unicode_transform transform;
	buffer_t *buffer;
};

void unicode_buffer_sink_init(struct unicode_buffer_sink *sink,
			      buffer_t *buffer);

/* Static Array Sink */

struct unicode_static_array_sink {
	struct unicode_transform transform;
	uint32_t *array;
	size_t array_size;
	size_t *array_pos;
};

void unicode_static_array_sink_init(struct unicode_static_array_sink *sink,
				    uint32_t *array, size_t array_size,
				    size_t *array_pos);

/*
 * RFC 5051 - Simple Unicode Collation Algorithm
 */

struct unicode_rfc5051_context {
	uint32_t buffer[3];
};

void unicode_rfc5051_init(struct unicode_rfc5051_context *ctx);
size_t unicode_rfc5051_normalize(struct unicode_rfc5051_context *ctx,
				 uint32_t cp, const uint32_t **norm_r);

#endif
