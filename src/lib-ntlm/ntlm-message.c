/*
 * NTLM message handling.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published 
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

const char * __ntlmssp_t_str(const void *message, struct ntlmssp_buffer *buffer)
{
	unsigned int len = read_le16(&buffer->length) / sizeof(ucs2le_t);
	string_t *str = t_str_new(len / 2);
	const char *p = ((char *) message) + read_le32(&buffer->offset);

	while (len-- > 0) {
		str_append_c(str, *p & 0x7f);
		p += sizeof(ucs2le_t);
	}

	return str_c(str);
}

static unsigned int append_string(buffer_t *buf, const char *str, int ucase)
{
	unsigned int length = 0;

	for ( ; *str; str++) {
		buffer_append_c(buf, ucase ? toupper(*str) : *str);
		buffer_append_c(buf, 0);
		length += sizeof(ucs2le_t);
	}

	return length;
}

static void ntlmssp_append_string(buffer_t *buf, size_t buffer_offset,
				  const char *str)
{
	struct ntlmssp_buffer buffer;
	unsigned int length;

	write_le32(&buffer.offset, buffer_get_used_size(buf));

	length = append_string(buf, str, 0);

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

	write_le32(&buffer.offset, buffer_get_used_size(buf));

	va_start(args, buffer_offset);

	do {
		const char *data;
		type = va_arg(args, int);

		memset(&info, 0, sizeof(info));
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
				length = append_string(buf, data, 0);
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
	uint32_t flags = NTLMSSP_NEGOTIATE_UNICODE |
			 NTLMSSP_NEGOTIATE_NTLM |
			 NTLMSSP_NEGOTIATE_TARGET_INFO;

	if (client_flags & NTLMSSP_NEGOTIATE_NTLM2)
		flags |= NTLMSSP_NEGOTIATE_NTLM2;

	if (client_flags & NTLMSSP_REQUEST_TARGET)
		flags |= NTLMSSP_REQUEST_TARGET | NTLMSSP_TARGET_TYPE_SERVER;

	return flags;
}

const struct ntlmssp_challenge *
ntlmssp_create_challenge(pool_t pool, const struct ntlmssp_request *request,
			 size_t *size)
{
	buffer_t *buf;
	uint32_t flags = ntlmssp_flags(read_le32(&request->flags));
	struct ntlmssp_challenge c;

	buf = buffer_create_dynamic(pool, sizeof(struct ntlmssp_challenge));

	memset(&c, 0, sizeof(c));
	write_le64(&c.magic, NTLMSSP_MAGIC);
	write_le32(&c.type, NTLMSSP_MSG_TYPE2);
	write_le32(&c.flags, flags);
	random_fill(c.challenge, sizeof(c.challenge));

	buffer_write(buf, 0, &c, sizeof(c));

	if (flags & NTLMSSP_TARGET_TYPE_SERVER)
		ntlmssp_append_string(buf,
			offsetof(struct ntlmssp_challenge, target_name),
			my_hostname);

	ntlmssp_append_target_info(buf, offsetof(struct ntlmssp_challenge,
						 target_info),
				   NTPLMSSP_V2_TARGET_FQDN, my_hostname,
				   NTPLMSSP_V2_TARGET_END);

	*size = buffer_get_used_size(buf);
	return buffer_free_without_data(buf);
}

static int ntlmssp_check_buffer(const struct ntlmssp_buffer *buffer,
				size_t data_size, const char **error)
{
	uint32_t offset = read_le32(&buffer->offset);

	if (offset >= data_size) {
		*error = "buffer offset out of bounds";
		return 0;
	}

	if (offset + read_le16(&buffer->space) > data_size) {
		*error = "buffer end out of bounds";
		return 0;
	}

	return 1;
}

int ntlmssp_check_request(const struct ntlmssp_request *request,
			  size_t data_size, const char **error)
{
	uint32_t flags;

	if (data_size < sizeof(struct ntlmssp_request)) {
		*error = "request too short";
		return 0;
	}

	if (read_le64(&request->magic) != NTLMSSP_MAGIC) {
		*error = "signature mismatch";
		return 0;
	}

	if (read_le32(&request->type) != NTLMSSP_MSG_TYPE1) {
		*error = "message type mismatch";
		return 0;
	}

	flags = read_le32(&request->flags);

	if ((flags & NTLMSSP_NEGOTIATE_UNICODE) == 0) {
		*error = "client doesn't advertise Unicode support";
		return 0;
	}

	if ((flags & NTLMSSP_NEGOTIATE_NTLM) == 0) {
		*error = "client doesn't advertise NTLM support";
		return 0;
	}

	return 1;
}

int ntlmssp_check_response(const struct ntlmssp_response *response,
			   size_t data_size, const char **error)
{
	if (data_size < sizeof(struct ntlmssp_response)) {
		*error = "response too short";
		return 0;
	}

	if (read_le64(&response->magic) != NTLMSSP_MAGIC) {
		*error = "signature mismatch";
		return 0;
	}

	if (read_le32(&response->type) != NTLMSSP_MSG_TYPE3) {
		*error = "message type mismatch";
		return 0;
	}

	if (!ntlmssp_check_buffer(&response->lm_response, data_size, error) ||
	    !ntlmssp_check_buffer(&response->ntlm_response, data_size, error) ||
	    !ntlmssp_check_buffer(&response->domain, data_size, error) ||
	    !ntlmssp_check_buffer(&response->user, data_size, error) ||
	    !ntlmssp_check_buffer(&response->workstation, data_size, error))
		return 0;

	return 1;
}
