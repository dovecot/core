
#include "lib.h"
#include "buffer.h"
#include "md5.h"
#include "hex-binary.h"
#include "safe-memset.h"
#include "password-scheme.h"

void *ucs2be_str(pool_t pool, const char *str, size_t *size);

/*
 * Convert string to big-endian ucs2.
 */
void *ucs2be_str(pool_t pool, const char *str, size_t *size)
{
	buffer_t *buf = buffer_create_dynamic(pool, 32);

	while (*str) {
		buffer_append_c(buf, '\0');
		buffer_append_c(buf, *str++);
	}

	*size = buffer_get_used_size(buf);
	return buffer_free_without_data(&buf);
}

void password_generate_rpa(const char *pw, unsigned char result[])
{
	unsigned char *ucs2be_pw;
	size_t size;

	ucs2be_pw = ucs2be_str(unsafe_data_stack_pool, pw, &size);
	md5_get_digest(ucs2be_pw, size, result);
	safe_memset(ucs2be_pw, 0, size);
}
