/*
 * NTLM message handling.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "str.h"
#include "buffer.h"
#include "hostpid.h"
#include "randgen.h"

#include "ntlm.h"
#include "ntlm-message.h"

#include <stdarg.h>
#include <ctype.h>

const char *ntlmssp_t_str_i(const void *message, struct ntlmssp_buffer *buffer,
			    bool unicode)
{
	unsigned int len = read_le16(&buffer->length);
	const char *p = ((const char *) message) + read_le32(&buffer->offset);
	string_t *str;

	if (unicode)
		len /= sizeof(ucs2le_t);

	str = t_str_new(len);

	while (len-- > 0) {
		str_append_c(str, *p & 0x7f);
		p += unicode ? sizeof(ucs2le_t) : 1;
	}

	return str_c(str);
}

static unsigned int append_string(buffer_t *buf, const char *str, 
				  bool ucase, bool unicode)
{
	unsigned int length = 0;

	for ( ; *str != '\0'; str++) {
		buffer_append_c(buf, ucase ? i_toupper(*str) : *str);
		if (unicode) {
			buffer_append_c(buf, 0);
			length++; 
		}
		length++;
	}

	return length;
}

static void ntlmssp_append_string(buffer_t *buf, size_t buffer_offset,
				  const char *str, bool unicode)
{
	struct ntlmssp_buffer buffer;
	unsigned int length;

	write_le32(&buffer.offset, buf->used);

	length = append_string(buf, str, FALSE, unicode);

	write_le16(&buffer.length, length);
	write_le16(&buffer.space, length);
	buffer_write(buf, buffer_offset, &buffer, sizeof(buffer));
}

static void ntlmssp_append_target_info(buffer_t *buf, size_t buffer_offset, ...)
{
	struct ntlmssp_v2_target_info info;
	struct ntlmssp_buffer buffer;
	va_list args;
	unsigned int length, total_length = 0;
	int type;

	write_le32(&buffer.offset, buf->used);

	va_start(args, buffer_offset);

	do {
		const char *data;
		type = va_arg(args, int);

		i_zero(&info);
		write_le16(&info.type, type);

		switch (type) {
			case NTPLMSSP_V2_TARGET_END:
				buffer_append(buf, &info, sizeof(info));
				length = sizeof(info);
				break;
			case NTPLMSSP_V2_TARGET_SERVER:
			case NTPLMSSP_V2_TARGET_DOMAIN:
			case NTPLMSSP_V2_TARGET_FQDN:
			case NTPLMSSP_V2_TARGET_DNS:
				data = va_arg(args, const char *);
				write_le16(&info.length,
					   strlen(data) * sizeof(ucs2le_t));
				buffer_append(buf, &info, sizeof(info));
				length = append_string(buf, data, FALSE, TRUE) +
					 sizeof(info);
				break;
			default:
				i_panic("Invalid NTLM target info block type "
					"%u", type);
		}

		total_length += length;
	
	} while (type != NTPLMSSP_V2_TARGET_END);

	va_end(args);

	write_le16(&buffer.length, total_length);
	write_le16(&buffer.space, total_length);
	buffer_write(buf, buffer_offset, &buffer, sizeof(buffer));
}

static inline uint32_t ntlmssp_flags(uint32_t client_flags)
{
	uint32_t flags = NTLMSSP_NEGOTIATE_NTLM |
			 NTLMSSP_NEGOTIATE_TARGET_INFO;

	if ((client_flags & NTLMSSP_NEGOTIATE_UNICODE) != 0)
		flags |= NTLMSSP_NEGOTIATE_UNICODE;
	else
		flags |= NTLMSSP_NEGOTIATE_OEM;

	if ((client_flags & NTLMSSP_NEGOTIATE_NTLM2) != 0)
		flags |= NTLMSSP_NEGOTIATE_NTLM2;

	if ((client_flags & NTLMSSP_REQUEST_TARGET) != 0)
		flags |= NTLMSSP_REQUEST_TARGET | NTLMSSP_TARGET_TYPE_SERVER;

	return flags;
}

const struct ntlmssp_challenge *
ntlmssp_create_challenge(pool_t pool, const struct ntlmssp_request *request,
			 size_t *size)
{
	buffer_t *buf;
	uint32_t flags = ntlmssp_flags(read_le32(&request->flags));
	bool unicode = (flags & NTLMSSP_NEGOTIATE_UNICODE) != 0;
	struct ntlmssp_challenge c;

	buf = buffer_create_dynamic(pool, sizeof(struct ntlmssp_challenge));

	i_zero(&c);
	write_le64(&c.magic, NTLMSSP_MAGIC);
	write_le32(&c.type, NTLMSSP_MSG_TYPE2);
	write_le32(&c.flags, flags);
	random_fill(c.challenge, sizeof(c.challenge));

	buffer_write(buf, 0, &c, sizeof(c));

	if ((flags & NTLMSSP_TARGET_TYPE_SERVER) != 0)
		ntlmssp_append_string(buf,
			offsetof(struct ntlmssp_challenge, target_name),
			my_hostname, unicode);

	ntlmssp_append_target_info(buf, offsetof(struct ntlmssp_challenge,
						 target_info),
				   NTPLMSSP_V2_TARGET_FQDN, my_hostname,
				   NTPLMSSP_V2_TARGET_END);

	*size = buf->used;
	return buffer_free_without_data(&buf);
}

static bool ntlmssp_check_buffer(const struct ntlmssp_buffer *buffer,
				 size_t data_size, const char **error)
{
	uint32_t offset = read_le32(&buffer->offset);
	uint16_t length = read_le16(&buffer->length);
	uint16_t space = read_le16(&buffer->space);

	/* Empty buffer is ok */
	if (length == 0 && space == 0)
		return TRUE;

	if (length > data_size) {
		*error = "buffer length out of bounds";
		return FALSE;
	}

	if (offset >= data_size) {
		*error = "buffer offset out of bounds";
		return FALSE;
	}

	if (offset + space > data_size) {
		*error = "buffer end out of bounds";
		return FALSE;
	}

	return TRUE;
}

bool ntlmssp_check_request(const struct ntlmssp_request *request,
			   size_t data_size, const char **error)
{
	uint32_t flags;

	if (data_size < sizeof(struct ntlmssp_request)) {
		*error = "request too short";
		return FALSE;
	}

	if (read_le64(&request->magic) != NTLMSSP_MAGIC) {
		*error = "signature mismatch";
		return FALSE;
	}

	if (read_le32(&request->type) != NTLMSSP_MSG_TYPE1) {
		*error = "message type mismatch";
		return FALSE;
	}

	flags = read_le32(&request->flags);

	if ((flags & NTLMSSP_NEGOTIATE_NTLM) == 0) {
		*error = "client doesn't advertise NTLM support";
		return FALSE;
	}

	return TRUE;
}

bool ntlmssp_check_response(const struct ntlmssp_response *response,
			    size_t data_size, const char **error)
{
	if (data_size < sizeof(struct ntlmssp_response)) {
		*error = "response too short";
		return FALSE;
	}

	if (read_le64(&response->magic) != NTLMSSP_MAGIC) {
		*error = "signature mismatch";
		return FALSE;
	}

	if (read_le32(&response->type) != NTLMSSP_MSG_TYPE3) {
		*error = "message type mismatch";
		return FALSE;
	}

	if (!ntlmssp_check_buffer(&response->lm_response, data_size, error) ||
	    !ntlmssp_check_buffer(&response->ntlm_response, data_size, error) ||
	    !ntlmssp_check_buffer(&response->domain, data_size, error) ||
	    !ntlmssp_check_buffer(&response->user, data_size, error) ||
	    !ntlmssp_check_buffer(&response->workstation, data_size, error))
		return FALSE;

	return TRUE;
}
