/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "numpack.h"
#include "message-binary-part.h"

void message_binary_part_serialize(const struct message_binary_part *parts,
				   buffer_t *dest)
{
	const struct message_binary_part *part;

	for (part = parts; part != NULL; part = part->next) {
		numpack_encode(dest, part->physical_pos);
		numpack_encode(dest, part->binary_hdr_size);
		numpack_encode(dest, part->binary_body_size);
		numpack_encode(dest, part->binary_body_lines_count);
	}
}

int message_binary_part_deserialize(pool_t pool, const void *data, size_t size,
				    struct message_binary_part **parts_r)
{
	const uint8_t *p = data, *end = p + size;
	uint64_t n1, n2, n3, n4;
	struct message_binary_part *part = NULL, *prev_part = NULL;

	while (p != end) {
		part = p_new(pool, struct message_binary_part, 1);
		part->next = prev_part;
		prev_part = part;
		if (numpack_decode(&p, end, &n1) < 0 ||
		    numpack_decode(&p, end, &n2) < 0 ||
		    numpack_decode(&p, end, &n3) < 0 ||
		    numpack_decode(&p, end, &n4) < 0)
			return -1;
		part->physical_pos = n1;
		part->binary_hdr_size = n2;
		part->binary_body_size = n3;
		part->binary_body_lines_count = n4;
	}
	*parts_r = part;
	return 0;
}
