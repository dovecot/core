#ifndef NTLM_H
#define NTLM_H

#include <stddef.h>

#include "ntlm-types.h"
#include "ntlm-flags.h"
#include "ntlm-byteorder.h"
#include "ntlm-encrypt.h"
#include "ntlm-message.h"

#define ntlmssp_buffer_data(message, buffer) \
	__ntlmssp_buffer_data((message), &message->buffer)

static inline const void *
__ntlmssp_buffer_data(void * message, struct ntlmssp_buffer *buffer)
{
	return ((char *) message) + read_le32(&buffer->offset);
}

#define ntlmssp_buffer_length(message, buffer) \
	__ntlmssp_buffer_length(&message->buffer)

static inline unsigned int __ntlmssp_buffer_length(struct ntlmssp_buffer *buffer)
{
	return read_le16(&buffer->length);
}

#define ntlmssp_t_str(message, buffer, unicode) \
	__ntlmssp_t_str((message), &(message)->buffer, (unicode))

const char * __ntlmssp_t_str(const void *message,
			     struct ntlmssp_buffer *buffer,
			     bool unicode);

#endif
