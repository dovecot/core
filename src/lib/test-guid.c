/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "guid.h"
#include "ioloop.h"

/*
 * We want earlier timestamps to compare as < with later timestamps, but
 * guid_128_cmp() doesn't do that because the timestamps in the guid are
 * stored in little-endian byte order.
 */
static int reverse_guid_128_cmp(const guid_128_t a, const guid_128_t b)
{
	int i;

	for (i = GUID_128_SIZE - 1; i >= 0; i--)
		if (a[i] != b[i])
			return (int)a[i] - (int)b[i];

	return 0;
}

static bool guid_128_has_sane_nsecs(const guid_128_t g)
{
	unsigned long nsecs;

	nsecs = (g[3] << 24) | (g[2] << 16) | (g[1] << 8) | g[0];

	return nsecs < 1000000000UL;
}

static inline void set_fake_time(time_t sec, long usec)
{
	ioloop_timeval.tv_sec = sec;
	ioloop_timeval.tv_usec = usec;
}

/*
 * We muck with the ioloop_timeval in various ways and make sure that the
 * guids that get generated make sense.  To make sure that the guid
 * generation code takes up our faked timestamp, we use a far-away time (Jan
 * 1 2038) as the base time.  We don't want to go beyond 32-bit signed
 * time_t for the base time to avoid issues on systems with 32-bit signed
 * time_t.
 *
 * While guids really only need to be unique, here we actually enforce that
 * they are increasing (as defined by reverse_guid_128_cmp()).  If guids are
 * always increasing, they will always be unique.
 */
static void test_ioloop_guid_128_generate(void)
{
	const time_t basetime = 2145909600; /* Jan 1 2038 */
	struct timeval saved_ioloop_timeval;
	guid_128_t guids[2];
	int i;

	/* save the ioloop_timeval before we start messing with it */
	saved_ioloop_timeval = ioloop_timeval;

	/*
	 * Generating multiple guids within a microsecond should keep
	 * incrementing them.
	 */
	test_begin("guid_128_generate() increasing guid within a usec");
	set_fake_time(basetime, 0);
	guid_128_generate(guids[1]);
	for (i = 0; i < 10; i++) {
		const int this = i % 2;
		const int prev = 1 - this;

		guid_128_generate(guids[this]);

		test_assert(reverse_guid_128_cmp(guids[prev], guids[this]) < 0);
		test_assert(guid_128_has_sane_nsecs(guids[this]));
	}
	test_end();

	/*
	 * If the current time changes by +1 usec, so should the guids.
	 */
	test_begin("guid_128_generate() increasing guid with usec fast-forward");
	for (i = 0; i < 10; i++) {
		const int this = i % 2;
		const int prev = 1 - this;

		set_fake_time(basetime, 1 + i);
		guid_128_generate(guids[this]);

		test_assert(reverse_guid_128_cmp(guids[prev], guids[this]) < 0);
		test_assert(guid_128_has_sane_nsecs(guids[this]));
	}
	test_end();

	/*
	 * If the current time changes by +1 sec, so should the guids.
	 */
	test_begin("guid_128_generate() increasing guid with sec fast-forward");
	for (i = 0; i < 10; i++) {
		const int this = i % 2;
		const int prev = 1 - this;

		set_fake_time(basetime + 1 + i, 0);
		guid_128_generate(guids[this]);

		test_assert(reverse_guid_128_cmp(guids[prev], guids[this]) < 0);
		test_assert(guid_128_has_sane_nsecs(guids[this]));
	}
	test_end();

	/*
	 * Requesting enough guids should increment the seconds but always
	 * produce valid nsecs.
	 *
	 * (Set a time that leaves us 1000 guids before seconds overflow and
	 * then ask for 2500 guids.)
	 */
	test_begin("guid_128_generate() proper guid nsec overflow");
	set_fake_time(basetime + 11, 999999L);
	for (i = 0; i < 2500; i++) {
		const int this = i % 2;
		const int prev = 1 - this;

		guid_128_generate(guids[this]);
		test_assert(reverse_guid_128_cmp(guids[prev], guids[this]) < 0);
		test_assert(guid_128_has_sane_nsecs(guids[this]));
	}
	test_end();

	/*
	 * When ahead by 1500 guids (see previous test), +1 usec shouldn't
	 * have any effect.
	 */
	test_begin("guid_128_generate() no effect with increasing time when ahead");
	set_fake_time(basetime + 12, 0);
	guid_128_generate(guids[0]);
	test_assert(reverse_guid_128_cmp(guids[1], guids[0]) < 0);
	test_assert(guid_128_has_sane_nsecs(guids[0]));
	test_end();

	/* not a test - just set a more convenient time */
	set_fake_time(basetime + 15, 500);
	guid_128_generate(guids[1]);
	test_assert(reverse_guid_128_cmp(guids[0], guids[1]) < 0);
	test_assert(guid_128_has_sane_nsecs(guids[1]));

	/*
	 * Time going backwards by 1 usec should have no effect on guids.
	 */
	test_begin("guid_128_generate() usec time-travel still increasing");
	set_fake_time(basetime + 15, 499);
	guid_128_generate(guids[0]);
	test_assert(reverse_guid_128_cmp(guids[1], guids[0]) < 0);
	test_assert(guid_128_has_sane_nsecs(guids[0]));
	test_end();

	/*
	 * Time going backwards by 1 sec should have no effect on guids.
	 */
	test_begin("guid_128_generate() sec time-travel still increasing");
	set_fake_time(basetime + 14, 499);
	guid_128_generate(guids[1]);
	test_assert(reverse_guid_128_cmp(guids[0], guids[1]) < 0);
	test_assert(guid_128_has_sane_nsecs(guids[1]));
	test_end();

	/* restore the previously saved value just in case */
	ioloop_timeval = saved_ioloop_timeval;
}

void test_guid(void)
{
	static const guid_128_t test_guid =
	{ 0x01, 0x23, 0x45, 0x67, 0x89,
	  0xab, 0xcd, 0xef,
	  0xAB, 0xCD, 0xEF,
	  0x00, 0x00, 0x00, 0x00, 0x00 };
	guid_128_t guid1, guid2, guid3;
	const char *str;
	char guidbuf[GUID_128_SIZE*2 + 2];
	unsigned int i;

	test_begin("guid_128_generate()");
	guid_128_generate(guid1);
	guid_128_generate(guid2);
	test_assert(!guid_128_equals(guid1, guid2));
	test_assert(guid_128_cmp(guid1, guid2) != 0);
	test_end();

	test_begin("guid_128_is_empty()");
	test_assert(!guid_128_is_empty(guid1));
	test_assert(!guid_128_is_empty(guid2));
	guid_128_generate(guid3);
	guid_128_empty(guid3);
	test_assert(guid_128_is_empty(guid3));
	test_end();

	test_begin("guid_128_copy()");
	guid_128_copy(guid3, guid1);
	test_assert(guid_128_equals(guid3, guid1));
	test_assert(!guid_128_equals(guid3, guid2));
	guid_128_copy(guid3, guid2);
	test_assert(!guid_128_equals(guid3, guid1));
	test_assert(guid_128_equals(guid3, guid2));
	test_end();

	test_begin("guid_128_to_string()");
	str = guid_128_to_string(guid1);
	test_assert(guid_128_from_string(str, guid3) == 0);
	test_assert(guid_128_equals(guid3, guid1));
	test_end();

	test_begin("guid_128_from_string()");
	/* empty */
	memset(guidbuf, '0', GUID_128_SIZE*2);
	guidbuf[GUID_128_SIZE*2] = '\0';
	guidbuf[GUID_128_SIZE*2+1] = '\0';
	test_assert(guid_128_from_string(guidbuf, guid3) == 0);
	test_assert(guid_128_is_empty(guid3));
	/* too large */
	guidbuf[GUID_128_SIZE*2] = '0';
	test_assert(guid_128_from_string(guidbuf, guid3) < 0);
	/* too small */
	guidbuf[GUID_128_SIZE*2-1] = '\0';
	test_assert(guid_128_from_string(guidbuf, guid3) < 0);
	/* reset to normal */
	guidbuf[GUID_128_SIZE*2-1] = '0';
	guidbuf[GUID_128_SIZE*2] = '\0';
	test_assert(guid_128_from_string(guidbuf, guid3) == 0);
	/* upper + lowercase hex chars */
	i_assert(GUID_128_SIZE*2 > 16 + 6);
	for (i = 0; i < 10; i++)
		guidbuf[i] = '0' + i;
	for (i = 0; i < 6; i++)
		guidbuf[10 + i] = 'a' + i;
	for (i = 0; i < 6; i++)
		guidbuf[16 + i] = 'A' + i;
	test_assert(guid_128_from_string(guidbuf, guid3) == 0);
	test_assert(guid_128_equals(guid3, test_guid));
	/* non-hex chars */
	guidbuf[0] = 'g';
	test_assert(guid_128_from_string(guidbuf, guid3) < 0);
	guidbuf[0] = ' ';
	test_assert(guid_128_from_string(guidbuf, guid3) < 0);

	test_assert(guid_128_from_uuid_string("fee0ceac-0327-11e7-ad39-52540078f374", guid3) == 0);
	test_assert(guid_128_from_uuid_string("fee0ceac032711e7ad3952540078f374", guid2) == 0);
	test_assert(guid_128_cmp(guid3, guid2) == 0);
	test_assert(guid_128_from_uuid_string("{fee0ceac-0327-11e7-ad39-52540078f374}", guid2) == 0);
	test_assert(guid_128_cmp(guid3, guid2) == 0);
	test_assert(strcmp(guid_128_to_uuid_string(guid3, FORMAT_RECORD), "fee0ceac-0327-11e7-ad39-52540078f374")==0);
	test_assert(strcmp(guid_128_to_uuid_string(guid3, FORMAT_COMPACT), "fee0ceac032711e7ad3952540078f374")==0);
	test_assert(strcmp(guid_128_to_uuid_string(guid3, FORMAT_MICROSOFT), "{fee0ceac-0327-11e7-ad39-52540078f374}")==0);
	/* failure test */
	test_assert(guid_128_from_uuid_string("fe-e0ceac-0327-11e7-ad39-52540078f374", guid3) < 0);

	test_end();

	test_ioloop_guid_128_generate();
}
