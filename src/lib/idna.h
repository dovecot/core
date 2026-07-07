#ifndef IDNA_H
#define IDNA_H

#define IDNA_DNS_MAX_LABEL_LENGTH 63
#define IDNA_DNS_MAX_NAME_LENGTH 254

/* Unicode® Technical Standard #46, Section 4:
 *
 * Input:
 */
enum idna_process_flags {
	/* A boolean flag: UseSTD3ASCIIRules - inverted */
	IDNA_PROCESS_FLAG_IGNORE_STD3_ASCII_RULES = BIT(0),
	/* A boolean flag: CheckHyphens */
	IDNA_PROCESS_FLAG_CHECK_HYPHENS = BIT(1),
	/* A boolean flag: CheckBidi - always FALSE
	   NOT IMPLEMENTED */
	/* A boolean flag: CheckJoiners - always FALSE
	   NOT IMPLEMENTED */
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
