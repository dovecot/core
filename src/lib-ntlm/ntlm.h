#ifndef NTLM_H
#define NTLM_H

#include <stddef.h>

#include "ntlm-types.h"
#include "ntlm-flags.h"
#include "ntlm-byteorder.h"
#include "ntlm-encrypt.h"
#include "ntlm-message.h"

#define ntlmssp_buffer_data(message, buffer) \
	ntlmssp_buffer_data_i((message), &message->buffer)

static inline const void *
ntlmssp_buffer_data_i(void *message, struct ntlmssp_buffer *buffer)
{
	return ((char *) message) + read_le32(&buffer->offset);
}

#define ntlmssp_buffer_length(message, buffer) \
	ntlmssp_buffer_length_i(&message->buffer)

static inline unsigned int
ntlmssp_buffer_length_i(struct ntlmssp_buffer *buffer)
{
	return read_le16(&buffer->length);
}

#define ntlmssp_t_str(message, buffer, unicode) \
	ntlmssp_t_str_i((message), &(message)->buffer, (unicode))

const char *ntlmssp_t_str_i(const void *message, struct ntlmssp_buffer *buffer,
			    bool unicode);

#endif
