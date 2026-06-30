/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "fuzzer.h"
#include "message-date.h"

FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	time_t t ATTR_UNUSED;
	int tz ATTR_UNUSED;
	(void)message_date_parse(data, size, &t, &tz);
}
FUZZ_END
