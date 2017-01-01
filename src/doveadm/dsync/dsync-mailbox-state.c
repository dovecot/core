/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "base64.h"
#include "crc32.h"
#include "hash.h"
#include "dsync-mailbox-state.h"

#define DSYNC_STATE_MAJOR_VERSION 1
#define DSYNC_STATE_MINOR_VERSION 0

#define V0_MAILBOX_SIZE (GUID_128_SIZE + 4 + 4 + 8 + 8)
#define MAILBOX_SIZE (GUID_128_SIZE + 4 + 4 + 8 + 8 + 4)

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

void dsync_mailbox_states_export(const HASH_TABLE_TYPE(dsync_mailbox_state) states,
				 string_t *output)
{
	struct hash_iterate_context *iter;
	struct dsync_mailbox_state *state;
	uint8_t *guid;
	buffer_t *buf = buffer_create_dynamic(pool_datastack_create(), 128);
	uint32_t crc = 0;

	buffer_append_c(buf, DSYNC_STATE_MAJOR_VERSION);
	buffer_append_c(buf, DSYNC_STATE_MINOR_VERSION);
	buffer_append_c(buf, '\0');
	buffer_append_c(buf, '\0');

	iter = hash_table_iterate_init(states);
	while (hash_table_iterate(iter, states, &guid, &state)) {
		buffer_append(buf, state->mailbox_guid,
			      sizeof(state->mailbox_guid));
		put_uint32(buf, state->last_uidvalidity);
		put_uint32(buf, state->last_common_uid);
		put_uint32(buf, state->last_common_modseq & 0xffffffffU);
		put_uint32(buf, state->last_common_modseq >> 32);
		put_uint32(buf, state->last_common_pvt_modseq & 0xffffffffU);
		put_uint32(buf, state->last_common_pvt_modseq >> 32);
		put_uint32(buf, state->last_messages_count); /* v1 */
		if (buf->used % 3 == 0) {
			crc = crc32_data_more(crc, buf->data, buf->used);
			base64_encode(buf->data, buf->used, output);
			buffer_set_used_size(buf, 0);
		}
	}
	hash_table_iterate_deinit(&iter);

	crc = crc32_data_more(crc, buf->data, buf->used);
	put_uint32(buf, crc);
	base64_encode(buf->data, buf->used, output);
}

static int dsync_mailbox_states_retry_import_v0(const buffer_t *buf)
{
	const unsigned char *data = buf->data;

	/* v0 had no version header and no last_messages_count */

	if ((buf->used-4) % V0_MAILBOX_SIZE != 0 ||
	    get_uint32(data + buf->used-4) != crc32_data(data, buf->used-4))
		return -1;
	/* looks like valid v0 format, silently treat it as empty state */
	return 0;
}

int dsync_mailbox_states_import(HASH_TABLE_TYPE(dsync_mailbox_state) states,
				pool_t pool, const char *input,
				const char **error_r)
{
	struct dsync_mailbox_state *state;
	buffer_t *buf;
	uint8_t *guid_p;
	const unsigned char *data;
	size_t pos;
	unsigned int i, count;

	buf = buffer_create_dynamic(pool_datastack_create(), strlen(input));
	if (base64_decode(input, strlen(input), &pos, buf) < 0) {
		*error_r = "Invalid base64 data";
		return -1;
	}
	/* v1: 4 byte header, mailboxes[], CRC32 */
	data = buf->data;

	if (buf->used == 4 && get_uint32(data) == 0) {
		/* v0: Empty state */
		return 0;
	}
	if (buf->used < 8) {
		*error_r = "Input too small";
		return -1;
	}

	if ((buf->used-8) % MAILBOX_SIZE != 0) {
		*error_r = "Invalid input size";
		return dsync_mailbox_states_retry_import_v0(buf);
	}

	if (get_uint32(data + buf->used-4) != crc32_data(data, buf->used-4)) {
		*error_r = "CRC32 mismatch";
		return dsync_mailbox_states_retry_import_v0(buf);
	}
	data += 4;
	count = (buf->used-8) / MAILBOX_SIZE;

	for (i = 0; i < count; i++, data += MAILBOX_SIZE) {
		state = p_new(pool, struct dsync_mailbox_state, 1);
		memcpy(state->mailbox_guid, data, GUID_128_SIZE);
		state->last_uidvalidity = get_uint32(data + GUID_128_SIZE);
		state->last_common_uid = get_uint32(data + GUID_128_SIZE + 4);
		state->last_common_modseq =
			get_uint32(data + GUID_128_SIZE + 8) |
			(uint64_t)get_uint32(data + GUID_128_SIZE + 12) << 32;
		state->last_common_pvt_modseq =
			get_uint32(data + GUID_128_SIZE + 16) |
			(uint64_t)get_uint32(data + GUID_128_SIZE + 20) << 32;
		state->last_messages_count = get_uint32(data + GUID_128_SIZE + 24);
		guid_p = state->mailbox_guid;
		hash_table_insert(states, guid_p, state);
	}
	return 0;
}
