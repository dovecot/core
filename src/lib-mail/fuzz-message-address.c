/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "fuzzer.h"
#include "message-address.h"

static void
fuzz_message_address_write(pool_t pool, const struct message_address *addr,
			   enum message_address_parse_flags flags)
{
	struct message_address_list list;
	string_t *str = t_str_new(128);

	message_address_write(str, addr);
	/* Parse the written form again, so the quoting and escaping done by
	   the writer is fed back into the parser. */
	message_address_parse_full(pool, str_data(str), str_len(str),
				   UINT_MAX, flags, &list);
	(void)message_address_first_to_string(addr);
}

FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	pool_t pool = pool_datastack_create();
	struct message_address_list list;
	struct message_address *path;
	enum message_address_parse_flags flags = 0;
	unsigned int max_addresses = UINT_MAX;

	/* The first byte selects the parse flags and the address limit. */
	if (size > 0) {
		if ((data[0] & 0x01) != 0)
			flags |= MESSAGE_ADDRESS_PARSE_FLAG_FILL_MISSING;
		if ((data[0] & 0x02) != 0)
			flags |= MESSAGE_ADDRESS_PARSE_FLAG_STRICT_DOTS;
		if ((data[0] & 0x04) != 0)
			max_addresses = data[0] >> 3;
		data++;
		size--;
	}

	message_address_parse_full(pool, data, size, max_addresses, flags,
				   &list);
	if (list.head != NULL)
		fuzz_message_address_write(pool, list.head, flags);

	if (message_address_parse_path(pool, data, size, &path) == 0)
		fuzz_message_address_write(pool, path, flags);
}
FUZZ_END
