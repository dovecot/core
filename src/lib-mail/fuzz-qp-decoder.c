/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fuzzer.h"
#include "buffer.h"
#include "qp-decoder.h"

FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	const char *error ATTR_UNUSED;
	size_t invalid_src_pos ATTR_UNUSED;

	buffer_t *buf = buffer_create_dynamic(default_pool, size);
	struct qp_decoder *decoder = qp_decoder_init(buf);

	(void)qp_decoder_more(decoder, data, size, &invalid_src_pos, &error);

	qp_decoder_finish(decoder, &error);
	qp_decoder_deinit(&decoder);
	buffer_free(&buf);
}
FUZZ_END
