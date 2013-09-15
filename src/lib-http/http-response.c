#include "lib.h"
#include "array.h"
#include "istream.h"

#include "http-response.h"

bool http_response_has_connection_option(const struct http_response *resp,
	const char *option)
{
	const char *const *opt_idx;

	if (!array_is_created(&resp->connection_options))
		return FALSE;
	array_foreach(&resp->connection_options, opt_idx) {
		if (strcasecmp(*opt_idx, option) == 0)
			return TRUE;
	}
	return FALSE;
}

int http_response_get_payload_size(const struct http_response *resp,
    uoff_t *size_r)
{
	if (resp->payload == NULL) {
		*size_r = 0;
		return 1;
	}

	return i_stream_get_size(resp->payload, TRUE, size_r);
}

