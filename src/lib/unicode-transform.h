#ifndef UNICODE_NF_H
#define UNICODE_NF_H

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
