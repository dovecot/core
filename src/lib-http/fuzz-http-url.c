
#include <stdint.h>

#include "lib.h"
#include "net.h"
#include "http-url.h"
#include "test-common.h"


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    T_BEGIN{
    struct http_url *urlp = NULL;
    const char *error = NULL;

    // Allocate string we null terminate
	char *new_data = malloc(size+1);
    memcpy(new_data, data, size);
	if (new_data == NULL)
        return 0;    
    new_data[size] = '\0';
    
	// Fuzz entrypoint
    pool_t pdata_stack = pool_datastack_create();
    http_url_parse(new_data, NULL, 0, pdata_stack, &urlp, &error);

    free(new_data);
    }T_END;


    return 0;
}

