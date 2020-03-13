
#include <stdint.h>

#include "lib.h"
#include "net.h"
#include "imap-url.h"
#include "test-common.h"


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    T_BEGIN{
    struct imap_url *urlp;
    const char *error = NULL;

    // Allocate new string that we can NULL terminate
	char *new_data = malloc(size+1);
    memcpy(new_data, data, size);
	if (new_data == NULL)
        return 0;    
    new_data[size] = '\0';
    
    // Fuzz entry
    imap_url_parse(new_data, NULL, IMAP_URL_PARSE_ALLOW_URLAUTH, &urlp, &error);

    free(new_data);
    }T_END;

    return 0;
}

