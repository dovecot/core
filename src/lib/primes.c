#include "lib.h"
#include "primes.h"

static const unsigned int primes[] = {
#define PRIME_SKIP_COUNT 3
	17,
	37,
	67,
	131,
	257, /* next from 2^8 */
	521,
	1031,
	2053,
	4099,
	8209,
	16411,
	32771,
	65537, /* next from 2^16 */
	131101,
	262147,
	524309,
	1048583,
	2097169,
	4194319,
	8388617,
	16777259, /* next from 2^24 */
	33554467,
	67108879,
	134217757,
	268435459,
	536870923,
	1073741827,
	2147483659U,
	4294967291U /* previous from 2^32 */
};

static const unsigned int primes_count = N_ELEMENTS(primes);

unsigned int primes_closest(unsigned int num)
{
	unsigned int i;

	for (i = 31; i > PRIME_SKIP_COUNT; i--) {
		if ((num & (1 << i)) != 0)
			return primes[i - PRIME_SKIP_COUNT];
	}
	return primes[0];
}
