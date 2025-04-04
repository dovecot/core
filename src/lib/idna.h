#ifndef IDNA_H
#define IDNA_H

#define IDNA_DNS_MAX_LABEL_LENGTH 63
#define IDNA_DNS_MAX_NAME_LENGTH 254

struct unicode_code_point_data;

/*
 * Bidi Checking
 */

enum idna_bidi_check_state {
	IDNA_BIDI_CHECK_STATE_START = 0,
	IDNA_BIDI_CHECK_STATE_RTL,
	IDNA_BIDI_CHECK_STATE_LTR,
};

struct idna_bidi_check_context {
	bool rtl_label:1;
	bool valid:1;
};

struct idna_bidi_checker {
	enum idna_bidi_check_state state;
	struct idna_bidi_check_context *ctx;

	bool en_present:1;
	bool an_present:1;
	bool label_can_end:1;
};

static inline void
idna_bidi_checker_context_init(struct idna_bidi_check_context *ctx_r)
{
	i_zero(ctx_r);
	ctx_r->valid = TRUE;
	ctx_r->rtl_label = FALSE;
}

void idna_bidi_checker_init(struct idna_bidi_checker *ibc_r,
			    struct idna_bidi_check_context *ctx);
void idna_bidi_checker_reset(struct idna_bidi_checker *ibc);

void idna_bidi_checker_input(struct idna_bidi_checker *ibc, uint32_t cp,
			     const struct unicode_code_point_data **cp_data);
int idna_bidi_checker_finish(struct idna_bidi_checker *ibc);

/*
 * Code point context checker
 */

struct idna_context_checker {
	struct {
		unsigned int state;
		bool ccc_virama;
	} rule_200c;
	struct {
		bool ccc_virama;
	} rule_200d;
	struct {
		unsigned int state;
	} rule_00b7;
	struct {
		unsigned int state;
	} rule_0375;
	struct {
		bool script_hebrew;
	} rule_05f3;
	struct {
		bool seen_cp;
		bool seen_script;
	} rule_30fb;
	struct {
		bool seen_basic;
		bool seen_extended;
	} rule_0660;

	bool other:1;
};

void idna_context_checker_init(struct idna_context_checker *icc_r, bool other);
void idna_context_checker_reset(struct idna_context_checker *icc);

bool idna_context_checker_has_rule(struct idna_context_checker *icc,
				   uint32_t cp);

int idna_context_checker_input(struct idna_context_checker *icc, uint32_t cp,
			       const struct unicode_code_point_data **cp_data,
			       const char **error_r);
int idna_context_checker_finish(struct idna_context_checker *icc,
				const char **error_r);

/* Unicode® Technical Standard #46, Section 4:
 *
 * Input:
 */
enum idna_process_flags {
	/* A boolean flag: UseSTD3ASCIIRules - inverted */
	IDNA_PROCESS_FLAG_IGNORE_STD3_ASCII_RULES = BIT(0),
	/* A boolean flag: CheckHyphens */
	IDNA_PROCESS_FLAG_CHECK_HYPHENS = BIT(1),
	/* A boolean flag: CheckBidi - inverted */
	IDNA_PROCESS_FLAG_IGNORE_BIDI = BIT(2),
	/* A boolean flag: CheckJoiners - inverted */
	IDNA_PROCESS_FLAG_IGNORE_JOINERS = BIT(3),
	/* A boolean flag: Transitional_Processing - always FALSE
	   NOT IMPLEMENTED (deprecated) */
	/* A boolean flag: VerifyDnsLength - always TRUE
	   NOT IMPLEMENTED (not useful) */
	/* A boolean flag: IgnoreInvalidPunycode - always FALSE
	   NOT IMPLEMENTED (not useful) */
};

/* Check validity of domain name with respect to IDNA rules and (optionally)
   normalize the domain name fully to Unicode and/or ASCII. The t_unicode_r and
   to_ascii_r arguments may be NULL, indicating that these results are not
   requested. Returns -1 upon error and 0 otherwise. If -1 is returned, error_r
   is set to the error message. */
int idna_process_domain_name(const char *domain_name,
			     enum idna_process_flags flags,
			     const char **to_unicode_r, const char **to_ascii_r,
			     const char **error_r);

#endif
