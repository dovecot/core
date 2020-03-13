#include <stdint.h>

#include "lib.h"
#include "str.h"
#include "test-common.h"
#include "unichar.h"
#include "imap-utf7.h"
#include "test-common.h"
#include "imap-quote.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 3)
        return 0;

	T_BEGIN{
	string_t *dest;
	dest = t_str_new(size);

    // allocate new data we NULL terminate
    char *new_data = malloc(size+1);
    memcpy(new_data, data, size);
    new_data[size] = '\0';

    // Fuzz entries
	imap_utf8_to_utf7(new_data, dest);
	imap_utf7_to_utf8(new_data, dest);
	imap_append_string_for_humans(dest, (const unsigned char *)new_data, size);

	str_free(&dest);
    free(new_data);
	}T_END;

    return 0;
}

