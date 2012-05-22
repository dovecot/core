/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "base64.h"
#include "crc32.h"
#include "dsync-mailbox-state.h"

#define MAILBOX_SIZE (GUID_128_SIZE + 4 + 4 + 8)

static void put_uint32(buffer_t *output, uint32_t num)
{
	buffer_append_c(output, num & 0xff);
	buffer_append_c(output, (num >> 8) & 0xff);
	buffer_append_c(output, (num >> 16) & 0xff);
	buffer_append_c(output, (num >> 24) & 0xff);
}

static uint32_t get_uint32(const unsigned char *data)
{
	return data[0] | (data[1] << 8) | (data[2] << 16) |
		((unsigned int)data[3] << 24);
}

void dsync_mailbox_states_export(const struct dsync_mailbox_state *states,
				 unsigned int states_count, string_t *output)
{
	buffer_t *buf = buffer_create_dynamic(pool_datastack_create(), 128);
	unsigned int i;

	for (i = 0; i < states_count; i++) {
		const struct dsync_mailbox_state *state = &states[i];

		buffer_append(buf, state->mailbox_guid,
			      sizeof(state->mailbox_guid));
		put_uint32(buf, state->last_uidvalidity);
		put_uint32(buf, state->last_common_uid);
		put_uint32(buf, state->last_common_modseq & 0xffffffffU);
		put_uint32(buf, state->last_common_modseq >> 32);
	}
	put_uint32(buf, crc32_data(buf->data, buf->used));
	base64_encode(buf->data, buf->used, output);
}

int dsync_mailbox_states_import(ARRAY_TYPE(dsync_mailbox_state) *states,
				const char *input, const char **error_r)
{
	struct dsync_mailbox_state *state;
	buffer_t *buf;
	const unsigned char *data;
	size_t pos;
	unsigned int i, count;

	buf = buffer_create_dynamic(pool_datastack_create(), strlen(input));
	if (base64_decode(input, strlen(input), &pos, buf) < 0) {
		*error_r = "Invalid base64 data";
		return -1;
	}
	if (buf->used < 4) {
		*error_r = "Input too small";
		return -1;
	}
	if ((buf->used-4) % MAILBOX_SIZE != 0) {
		*error_r = "Invalid input size";
		return -1;
	}
	data = buf->data;
	count = (buf->used-4) / MAILBOX_SIZE;

	if (get_uint32(data + buf->used-4) != crc32_data(data, buf->used-4)) {
		*error_r = "CRC32 mismatch";
		return -1;
	}

	for (i = 0; i < count; i++, data += MAILBOX_SIZE) {
		state = array_append_space(states);
		memcpy(state->mailbox_guid, data, GUID_128_SIZE);
		state->last_uidvalidity = get_uint32(data + GUID_128_SIZE);
		state->last_common_uid = get_uint32(data + GUID_128_SIZE + 4);
		state->last_common_modseq =
			get_uint32(data + GUID_128_SIZE + 8) |
			(uint64_t)get_uint32(data + GUID_128_SIZE + 12) << 32;
	}
	return 0;
}
