#ifndef UNICODE_NF_H
#define UNICODE_NF_H

#define UNICODE_NF_STREAM_SAFE_NON_STARTER_LEN 30
#define UNICODE_NF_BUFFER_SIZE (UNICODE_NF_STREAM_SAFE_NON_STARTER_LEN + 2)

struct unicode_code_point_data;

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

ssize_t unicode_transform_input_buf(struct unicode_transform *trans,
				    const struct unicode_transform_buffer *buf,
				    const char **error_r);
static inline ssize_t
unicode_transform_input(struct unicode_transform *trans,
			const uint32_t *in, size_t in_len, const char **error_r)
{
	struct unicode_transform_buffer buf = {
		.cp = in,
		.cp_count = in_len,
	};

	return unicode_transform_input_buf(trans, &buf, error_r);
}

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
 * NFD, NFKD, NFC, NFKC
 */

/* Unicode Standard Annex #15, Section 1.2:

   Unicode Normalization Forms are formally defined normalizations of Unicode
   strings which make it possible to determine whether any two Unicode strings
   are equivalent to each other. Depending on the particular Unicode
   Normalization Form, that equivalence can either be a canonical equivalence or
   a compatibility equivalence.

   Essentially, the Unicode Normalization Algorithm puts all combining marks in
   a specified order, and uses rules for decomposition and composition to
   transform each string into one of the Unicode Normalization Forms. A binary
   comparison of the transformed strings will then determine equivalence.

   The four Unicode Normalization Forms are summarized as follows:

     Normalization Form D  (NFD)   - Canonical Decomposition
     Normalization Form KD (NFKD)  - Compatibility Decomposition
     Normalization Form C  (NFC)   - Canonical Decomposition, followed by
                                     Canonical Composition
     Normalization Form KC (NFKC)  - Compatibility Decomposition, followed by
                                     Canonical Composition

   There are two forms of normalization that convert to composite characters:
   Normalization Form C and Normalization Form KC. The difference between these
   depends on whether the resulting text is to be a canonical equivalent to the
   original unnormalized text or a compatibility equivalent to the original
   unnormalized text. (In NFKC and NFKD, a K is used to stand for compatibility
   to avoid confusion with the C standing for composition.) Both types of
   normalization can be useful in different circumstances.
 */

enum unicode_nf_type {
	UNICODE_NFD,
	UNICODE_NFKD,
	UNICODE_NFC,
	UNICODE_NFKC,
};

struct unicode_nf_context {
	struct unicode_transform transform;

	size_t nonstarter_count;
	uint32_t cp_buffer[UNICODE_NF_BUFFER_SIZE];
	const struct unicode_code_point_data *
		cpd_buffer[UNICODE_NF_BUFFER_SIZE];
	size_t buffer_len, buffer_processed, buffer_output_max;

	size_t pending_decomp;
	uint32_t pending_cp;
	const struct unicode_code_point_data *pending_cpd;

	uint8_t nf_qc_mask;

	bool compose:1;
	bool canonical:1;
	bool finished:1;
};

void unicode_nf_init(struct unicode_nf_context *ctx_r,
		     enum unicode_nf_type type);
void unicode_nf_reset(struct unicode_nf_context *ctx);

/*
 * Normalization check
 */

struct unicode_nf_checker {
	const struct unicode_code_point_data *cpd_last;

	uint8_t nf_qc_mask;
	uint8_t nf_qc_yes;
	uint8_t nf_qc_no;

	uint32_t cp_buffer[UNICODE_NF_BUFFER_SIZE];
	size_t buffer_len;
	struct unicode_nf_context nf;
	struct unicode_transform sink;

	bool not_first_cp;
	bool compose:1;
	bool canonical:1;
};

void unicode_nf_checker_init(struct unicode_nf_checker *unc_r,
			     enum unicode_nf_type type);
void unicode_nf_checker_reset(struct unicode_nf_checker *unc);

int unicode_nf_checker_input(struct unicode_nf_checker *unc, uint32_t cp,
			     const struct unicode_code_point_data **cp_data);
int unicode_nf_checker_finish(struct unicode_nf_checker *unc);

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
