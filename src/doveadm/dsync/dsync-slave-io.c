/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "close-keep-errno.h"
#include "fd-set-nonblock.h"
#include "safe-mkstemp.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-seekable.h"
#include "istream-dot.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "master-service.h"
#include "mail-cache.h"
#include "mail-storage-private.h"
#include "dsync-serializer.h"
#include "dsync-deserializer.h"
#include "dsync-mail.h"
#include "dsync-mailbox.h"
#include "dsync-mailbox-state.h"
#include "dsync-mailbox-tree.h"
#include "dsync-slave-private.h"

#include <stdlib.h>

#define DSYNC_SLAVE_IO_TIMEOUT_MSECS (60*10*1000)
#define DSYNC_SLAVE_IO_OUTBUF_THROTTLE_SIZE (1024*128)

#define DSYNC_PROTOCOL_VERSION_MAJOR 3
#define DSYNC_HANDSHAKE_VERSION "VERSION\tdsync\t3\t0\n"

enum item_type {
	ITEM_NONE,

	ITEM_HANDSHAKE,
	ITEM_MAILBOX_STATE,
	ITEM_MAILBOX_TREE_NODE,
	ITEM_MAILBOX_DELETE,
	ITEM_MAILBOX,

	ITEM_MAIL_CHANGE,
	ITEM_MAIL_REQUEST,
	ITEM_MAIL,

	ITEM_MAILBOX_CACHE_FIELD,

	ITEM_END_OF_LIST
};

#define END_OF_LIST_LINE "."
static const struct {
	/* full human readable name of the item */
	const char *name;
	/* unique character identifying the item */
	char chr;
	const char *required_keys;
	const char *optional_keys;
} items[ITEM_END_OF_LIST+1] = {
	{ NULL, '\0', NULL, NULL },
	{ .name = "handshake",
	  .chr = 'H',
	  .optional_keys = "sync_ns_prefix sync_type "
	  	"guid_requests mails_have_guids"
	},
	{ .name = "mailbox_state",
	  .chr = 'S',
	  .required_keys = "mailbox_guid last_uidvalidity last_common_uid "
	  	"last_common_modseq"
	},
	{ .name = "mailbox_tree_node",
	  .chr = 'N',
	  .required_keys = "name existence",
	  .optional_keys = "mailbox_guid uid_validity "
	  	"last_renamed subscribed last_subscription_change"
	},
	{ .name = "mailbox_delete",
	  .chr = 'D',
	  .required_keys = "hierarchy_sep",
	  .optional_keys = "mailboxes dirs"
	},
	{ .name = "mailbox",
	  .chr = 'B',
	  .required_keys = "mailbox_guid uid_validity uid_next "
		"messages_count first_recent_uid highest_modseq",
	  .optional_keys = "cache_fields"
	},
	{ .name = "mail_change",
	  .chr = 'C',
	  .required_keys = "type uid",
	  .optional_keys = "guid hdr_hash modseq save_timestamp "
	  	"add_flags remove_flags final_flags "
	  	"keywords_reset keyword_changes"
	},
	{ .name = "mail_request",
	  .chr = 'R',
	  .optional_keys = "guid uid"
	},
	{ .name = "mail",
	  .chr = 'M',
	  .optional_keys = "guid uid pop3_uidl pop3_order received_date stream"
	},
	{ .name = "mailbox_cache_field",
	  .chr = 'c',
	  .required_keys = "name decision",
	  .optional_keys = "last_used"
	},

	{ "end_of_list", '\0', NULL, NULL }
};

struct dsync_slave_io {
	struct dsync_slave slave;

	char *name, *temp_path_prefix;
	int fd_in, fd_out;
	struct istream *input;
	struct ostream *output;
	struct io *io;
	struct timeout *to;

	struct dsync_serializer *serializers[ITEM_END_OF_LIST];
	struct dsync_deserializer *deserializers[ITEM_END_OF_LIST];

	pool_t ret_pool;
	struct dsync_deserializer_decoder *cur_decoder;

	struct istream *mail_output, *mail_input;
	struct dsync_mail *cur_mail;
	char mail_output_last;

	unsigned int version_received:1;
	unsigned int handshake_received:1;
	unsigned int has_pending_data:1;
};

static void dsync_slave_io_stop(struct dsync_slave_io *slave)
{
	i_stream_close(slave->input);
	o_stream_close(slave->output);
	io_loop_stop(current_ioloop);
}

static int dsync_slave_io_read_mail_stream(struct dsync_slave_io *slave)
{
	size_t size;

	if (i_stream_read(slave->mail_input) < 0) {
		if (slave->mail_input->stream_errno != 0) {
			errno = slave->mail_input->stream_errno;
			i_error("dsync(%s): read() failed: %m", slave->name);
			dsync_slave_io_stop(slave);
			return -1;
		}
		/* finished reading the mail stream */
		i_assert(slave->mail_input->eof);
		i_stream_seek(slave->mail_input, 0);
		slave->mail_input = NULL;
		return 1;
	}
	(void)i_stream_get_data(slave->mail_input, &size);
	i_stream_skip(slave->mail_input, size);
	return 0;
}

static void dsync_slave_io_input(struct dsync_slave_io *slave)
{
	if (slave->mail_input != NULL) {
		if (dsync_slave_io_read_mail_stream(slave) == 0)
			return;
	}
	slave->slave.io_callback(slave->slave.io_context);
}

static int dsync_slave_io_send_mail_stream(struct dsync_slave_io *slave)
{
	const unsigned char *data;
	unsigned char add;
	size_t i, size;
	int ret;

	while ((ret = i_stream_read_data(slave->mail_output,
					 &data, &size, 0)) > 0) {
		add = '\0';
		for (i = 0; i < size; i++) {
			if (data[i] == '\n') {
				if ((i == 0 && slave->mail_output_last != '\r') ||
				    (i > 0 && data[i-1] != '\r')) {
					/* missing CR */
					add = '\r';
					break;
				}
			} else if (data[i] == '.' &&
				   ((i == 0 && slave->mail_output_last == '\n') ||
				    (i > 0 && data[i-1] == '\n'))) {
				/* escape the dot */
				add = '.';
				break;
			}
		}

		if (i > 0) {
			o_stream_nsend(slave->output, data, i);
			slave->mail_output_last = data[i-1];
			i_stream_skip(slave->mail_output, i);
		}

		if (o_stream_get_buffer_used_size(slave->output) >= 4096) {
			if ((ret = o_stream_flush(slave->output)) < 0) {
				dsync_slave_io_stop(slave);
				return -1;
			}
			if (ret == 0) {
				/* continue later */
				o_stream_set_flush_pending(slave->output, TRUE);
				return 0;
			}
		}

		if (add != '\0') {
			o_stream_nsend(slave->output, &add, 1);
			slave->mail_output_last = add;
		}
	}
	i_assert(ret == -1);

	if (slave->mail_output->stream_errno != 0) {
		i_error("dsync(%s): read(%s) failed: %m",
			slave->name, i_stream_get_name(slave->mail_output));
		dsync_slave_io_stop(slave);
		return -1;
	}

	/* finished sending the stream */
	o_stream_nsend_str(slave->output, "\r\n.\r\n");
	i_stream_unref(&slave->mail_output);
	return 1;
}

static int dsync_slave_io_output(struct dsync_slave_io *slave)
{
	struct ostream *output = slave->output;
	int ret;

	if ((ret = o_stream_flush(output)) < 0)
		ret = 1;
	else if (slave->mail_output != NULL) {
		if (dsync_slave_io_send_mail_stream(slave) < 0)
			ret = 1;
	}
	timeout_reset(slave->to);

	if (!dsync_slave_is_send_queue_full(&slave->slave))
		slave->slave.io_callback(slave->slave.io_context);
	return ret;
}

static void dsync_slave_io_timeout(struct dsync_slave_io *slave)
{
	i_error("dsync(%s): I/O has stalled, no activity for %u seconds",
		slave->name, DSYNC_SLAVE_IO_TIMEOUT_MSECS/1000);
	dsync_slave_io_stop(slave);
}

static void dsync_slave_io_init(struct dsync_slave_io *slave)
{
	unsigned int i;

	fd_set_nonblock(slave->fd_in, TRUE);
	fd_set_nonblock(slave->fd_out, TRUE);

	slave->input = i_stream_create_fd(slave->fd_in, (size_t)-1, FALSE);
	slave->output = o_stream_create_fd(slave->fd_out, (size_t)-1, FALSE);
	slave->io = io_add(slave->fd_in, IO_READ, dsync_slave_io_input, slave);
	o_stream_set_no_error_handling(slave->output, TRUE);
	o_stream_set_flush_callback(slave->output, dsync_slave_io_output, slave);
	slave->to = timeout_add(DSYNC_SLAVE_IO_TIMEOUT_MSECS,
				dsync_slave_io_timeout, slave);
	o_stream_cork(slave->output);
	o_stream_nsend_str(slave->output, DSYNC_HANDSHAKE_VERSION);

	/* initialize serializers and send their headers to remote */
	for (i = 1; i < ITEM_END_OF_LIST; i++) T_BEGIN {
		const char *keys;

		keys = items[i].required_keys == NULL ? items[i].optional_keys :
			t_strconcat(items[i].required_keys, " ",
				    items[i].optional_keys, NULL);
		if (keys != NULL) {
			i_assert(items[i].chr != '\0');

			slave->serializers[i] =
				dsync_serializer_init(t_strsplit_spaces(keys, " "));
			o_stream_nsend(slave->output, &items[i].chr, 1);
			o_stream_nsend_str(slave->output,
				dsync_serializer_encode_header_line(slave->serializers[i]));
		}
	} T_END;
	o_stream_nsend_str(slave->output, ".\n");

	dsync_slave_flush(&slave->slave);
}

static void dsync_slave_io_deinit(struct dsync_slave *_slave)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;

	if (slave->cur_decoder != NULL)
		dsync_deserializer_decode_finish(&slave->cur_decoder);
	if (slave->mail_output != NULL)
		i_stream_unref(&slave->mail_output);

	timeout_remove(&slave->to);
	if (slave->io != NULL)
		io_remove(&slave->io);
	i_stream_destroy(&slave->input);
	o_stream_destroy(&slave->output);
	if (close(slave->fd_in) < 0)
		i_error("close(%s) failed: %m", slave->name);
	if (slave->fd_in != slave->fd_out) {
		if (close(slave->fd_out) < 0)
			i_error("close(%s) failed: %m", slave->name);
	}
	pool_unref(&slave->ret_pool);
	i_free(slave->temp_path_prefix);
	i_free(slave->name);
	i_free(slave);
}

static int dsync_slave_io_next_line(struct dsync_slave_io *slave,
				    const char **line_r)
{
	const char *line;

	line = i_stream_next_line(slave->input);
	if (line != NULL) {
		*line_r = line;
		return 1;
	}

	/* try reading some */
	switch (i_stream_read(slave->input)) {
	case -1:
		if (slave->input->stream_errno != 0) {
			errno = slave->input->stream_errno;
			i_error("read(%s) failed: %m", slave->name);
		} else {
			i_assert(slave->input->eof);
			i_error("read(%s) failed: EOF", slave->name);
		}
		dsync_slave_io_stop(slave);
		return -1;
	case 0:
		return 0;
	}
	*line_r = i_stream_next_line(slave->input);
	if (*line_r == NULL) {
		slave->has_pending_data = FALSE;
		return 0;
	}
	slave->has_pending_data = TRUE;
	return 1;
}

static void ATTR_FORMAT(3, 4) ATTR_NULL(2)
dsync_slave_input_error(struct dsync_slave_io *slave,
			struct dsync_deserializer_decoder *decoder,
			const char *fmt, ...)
{
	va_list args;
	const char *error;

	va_start(args, fmt);
	error = t_strdup_vprintf(fmt, args);
	if (decoder == NULL)
		i_error("dsync(%s): %s", slave->name, error);
	else {
		i_error("dsync(%s): %s: %s", slave->name,
			dsync_deserializer_decoder_get_name(decoder), error);
	}
	va_end(args);

	dsync_slave_io_stop(slave);
}

static void
dsync_slave_io_send_string(struct dsync_slave_io *slave, const string_t *str)
{
	i_assert(slave->mail_output == NULL);
	o_stream_nsend(slave->output, str_data(str), str_len(str));
}

static int dsync_slave_check_missing_deserializers(struct dsync_slave_io *slave)
{
	unsigned int i;
	int ret = 0;

	for (i = 1; i < ITEM_END_OF_LIST; i++) {
		if (slave->deserializers[i] == NULL &&
		    (items[i].required_keys != NULL ||
		     items[i].optional_keys != NULL)) {
			dsync_slave_input_error(slave, NULL,
				"Remote didn't handshake deserializer for %s",
				items[i].name);
			ret = -1;
		}
	}
	return ret;
}

static bool
dsync_slave_io_handshake(struct dsync_slave_io *slave, const char *line)
{
	enum item_type item = ITEM_NONE;
	const char *const *required_keys, *error;
	unsigned int i;

	if (slave->handshake_received)
		return TRUE;

	if (!slave->version_received) {
		if (!version_string_verify(line, "dsync",
					   DSYNC_PROTOCOL_VERSION_MAJOR)) {
			dsync_slave_input_error(slave, NULL,
				"Remote dsync doesn't use compatible protocol");
			return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
		}
		slave->version_received = TRUE;
		return FALSE;
	}

	if (strcmp(line, END_OF_LIST_LINE) == 0) {
		/* finished handshaking */
		if (dsync_slave_check_missing_deserializers(slave) < 0)
			return FALSE;
		slave->handshake_received = TRUE;
		return FALSE;
	}

	for (i = 1; i < ITEM_END_OF_LIST; i++) {
		if (items[i].chr == line[0]) {
			item = i;
			break;
		}
	}
	if (item == ITEM_NONE) {
		/* unknown deserializer, ignore */
		return FALSE;
	}

	required_keys = items[item].required_keys == NULL ? NULL :
		t_strsplit(items[item].required_keys, " ");
	if (dsync_deserializer_init(items[item].name,
				    required_keys, line + 1,
				    &slave->deserializers[item], &error) < 0) {
		dsync_slave_input_error(slave, NULL,
			"Remote sent invalid handshake for %s: %s",
			items[item].name, error);
	}
	return FALSE;
}

static enum dsync_slave_recv_ret
dsync_slave_io_input_next(struct dsync_slave_io *slave, enum item_type item,
			  struct dsync_deserializer_decoder **decoder_r)
{
	enum item_type line_item = ITEM_NONE;
	const char *line, *error;
	unsigned int i;

	i_assert(slave->mail_input == NULL);

	timeout_reset(slave->to);

	do {
		if (dsync_slave_io_next_line(slave, &line) <= 0)
			return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	} while (!dsync_slave_io_handshake(slave, line));

	if (strcmp(line, END_OF_LIST_LINE) == 0) {
		/* end of this list */
		return DSYNC_SLAVE_RECV_RET_FINISHED;
	}
	for (i = 1; i < ITEM_END_OF_LIST; i++) {
		if (*line == items[i].chr) {
			line_item = i;
			break;
		}
	}
	if (line_item != item) {
		dsync_slave_input_error(slave, NULL,
			"Received unexpected input %c != %c",
			*line, items[item].chr);
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}

	if (slave->cur_decoder != NULL)
		dsync_deserializer_decode_finish(&slave->cur_decoder);
	if (dsync_deserializer_decode_begin(slave->deserializers[item],
					    line+1, &slave->cur_decoder,
					    &error) < 0) {
		dsync_slave_input_error(slave, NULL, "Invalid input to %s: %s",
					items[item].name, error);
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	*decoder_r = slave->cur_decoder;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_io_send_handshake(struct dsync_slave *_slave,
			      const struct dsync_slave_settings *set)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);
	char sync_type[2];

	str_append_c(str, items[ITEM_HANDSHAKE].chr);
	encoder = dsync_serializer_encode_begin(slave->serializers[ITEM_HANDSHAKE]);
	if (set->sync_ns_prefix != NULL) {
		dsync_serializer_encode_add(encoder, "sync_ns_prefix",
					    set->sync_ns_prefix);
	}

	sync_type[0] = sync_type[1] = '\0';
	switch (set->sync_type) {
	case DSYNC_BRAIN_SYNC_TYPE_UNKNOWN:
		break;
	case DSYNC_BRAIN_SYNC_TYPE_FULL:
		sync_type[0] = 'f';
		break;
	case DSYNC_BRAIN_SYNC_TYPE_CHANGED:
		sync_type[0] = 'c';
		break;
	case DSYNC_BRAIN_SYNC_TYPE_STATE:
		sync_type[0] = 's';
		break;
	}
	i_assert(sync_type[0] != '\0');
	dsync_serializer_encode_add(encoder, "sync_type", sync_type);
	if (set->guid_requests)
		dsync_serializer_encode_add(encoder, "guid_requests", "");
	if (set->mails_have_guids)
		dsync_serializer_encode_add(encoder, "mails_have_guids", "");

	dsync_serializer_encode_finish(&encoder, str);
	dsync_slave_io_send_string(slave, str);
}

static enum dsync_slave_recv_ret
dsync_slave_io_recv_handshake(struct dsync_slave *_slave,
			      const struct dsync_slave_settings **set_r)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_slave_settings *set;
	const char *value;
	pool_t pool = slave->ret_pool;
	enum dsync_slave_recv_ret ret;

	ret = dsync_slave_io_input_next(slave, ITEM_HANDSHAKE, &decoder);
	if (ret != DSYNC_SLAVE_RECV_RET_OK) {
		if (ret != DSYNC_SLAVE_RECV_RET_TRYAGAIN) {
			i_error("dsync(%s): Unexpected input in handshake",
				slave->name);
			dsync_slave_io_stop(slave);
		}
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}

	p_clear(pool);
	set = p_new(pool, struct dsync_slave_settings, 1);

	if (dsync_deserializer_decode_try(decoder, "sync_ns_prefix", &value))
		set->sync_ns_prefix = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "sync_type", &value)) {
		switch (value[0]) {
		case 'f':
			set->sync_type = DSYNC_BRAIN_SYNC_TYPE_FULL;
			break;
		case 'c':
			set->sync_type = DSYNC_BRAIN_SYNC_TYPE_CHANGED;
			break;
		case 's':
			set->sync_type = DSYNC_BRAIN_SYNC_TYPE_STATE;
			break;
		default:
			dsync_slave_input_error(slave, decoder,
				"Unknown sync_type: %s", value);
			return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
		}
	}
	if (dsync_deserializer_decode_try(decoder, "guid_requests", &value))
		set->guid_requests = TRUE;
	if (dsync_deserializer_decode_try(decoder, "mails_have_guids", &value))
		set->mails_have_guids = TRUE;

	*set_r = set;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_io_send_end_of_list(struct dsync_slave *_slave)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;

	i_assert(slave->mail_output == NULL);

	o_stream_nsend_str(slave->output, END_OF_LIST_LINE"\n");
}

static void
dsync_slave_io_send_mailbox_state(struct dsync_slave *_slave,
				  const struct dsync_mailbox_state *state)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);

	str_append_c(str, items[ITEM_MAILBOX_STATE].chr);
	encoder = dsync_serializer_encode_begin(slave->serializers[ITEM_MAILBOX_STATE]);
	dsync_serializer_encode_add(encoder, "mailbox_guid",
				    guid_128_to_string(state->mailbox_guid));
	dsync_serializer_encode_add(encoder, "last_uidvalidity",
				    dec2str(state->last_uidvalidity));
	dsync_serializer_encode_add(encoder, "last_common_uid",
				    dec2str(state->last_common_uid));
	dsync_serializer_encode_add(encoder, "last_common_modseq",
				    dec2str(state->last_common_modseq));

	dsync_serializer_encode_finish(&encoder, str);
	dsync_slave_io_send_string(slave, str);
}

static enum dsync_slave_recv_ret
dsync_slave_io_recv_mailbox_state(struct dsync_slave *_slave,
				  struct dsync_mailbox_state *state_r)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_deserializer_decoder *decoder;
	const char *value;
	enum dsync_slave_recv_ret ret;

	memset(state_r, 0, sizeof(*state_r));

	ret = dsync_slave_io_input_next(slave, ITEM_MAILBOX_STATE, &decoder);
	if (ret != DSYNC_SLAVE_RECV_RET_OK)
		return ret;

	value = dsync_deserializer_decode_get(decoder, "mailbox_guid");
	if (guid_128_from_string(value, state_r->mailbox_guid) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid mailbox_guid");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "last_uidvalidity");
	if (str_to_uint32(value, &state_r->last_uidvalidity) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid last_uidvalidity");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "last_common_uid");
	if (str_to_uint32(value, &state_r->last_uidvalidity) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid last_common_uid");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "last_common_modseq");
	if (str_to_uint32(value, &state_r->last_uidvalidity) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid last_common_modseq");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_io_send_mailbox_tree_node(struct dsync_slave *_slave,
				      const char *const *name,
				      const struct dsync_mailbox_node *node)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_serializer_encoder *encoder;
	string_t *str, *namestr;

	i_assert(*name != NULL);

	str = t_str_new(128);
	str_append_c(str, items[ITEM_MAILBOX_TREE_NODE].chr);

	/* convert all hierarchy separators to tabs. mailbox names really
	   aren't supposed to have any tabs, but escape them anyway if there
	   are. */
	namestr = t_str_new(128);
	for (; *name != NULL; name++) {
		str_tabescape_write(namestr, *name);
		str_append_c(namestr, '\t');
	}
	str_truncate(namestr, str_len(namestr)-1);

	encoder = dsync_serializer_encode_begin(slave->serializers[ITEM_MAILBOX_TREE_NODE]);
	dsync_serializer_encode_add(encoder, "name", str_c(namestr));
	switch (node->existence) {
	case DSYNC_MAILBOX_NODE_NONEXISTENT:
		dsync_serializer_encode_add(encoder, "existence", "n");
		break;
	case DSYNC_MAILBOX_NODE_EXISTS:
		dsync_serializer_encode_add(encoder, "existence", "y");
		break;
	case DSYNC_MAILBOX_NODE_DELETED:
		dsync_serializer_encode_add(encoder, "existence", "d");
		break;
	}

	if (!guid_128_is_empty(node->mailbox_guid)) {
		dsync_serializer_encode_add(encoder, "mailbox_guid",
			guid_128_to_string(node->mailbox_guid));
	}
	if (node->uid_validity != 0) {
		dsync_serializer_encode_add(encoder, "uid_validity",
					    dec2str(node->uid_validity));
	}
	if (node->last_renamed != 0) {
		dsync_serializer_encode_add(encoder, "last_renamed",
					    dec2str(node->last_renamed));
	}
	if (node->last_subscription_change != 0) {
		dsync_serializer_encode_add(encoder, "last_subscription_change",
			dec2str(node->last_subscription_change));
	}
	if (node->subscribed)
		dsync_serializer_encode_add(encoder, "subscribed", "");
	dsync_serializer_encode_finish(&encoder, str);
	dsync_slave_io_send_string(slave, str);
}

static enum dsync_slave_recv_ret
dsync_slave_io_recv_mailbox_tree_node(struct dsync_slave *_slave,
				      const char *const **name_r,
				      const struct dsync_mailbox_node **node_r)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_mailbox_node *node;
	const char *value;
	enum dsync_slave_recv_ret ret;

	ret = dsync_slave_io_input_next(slave, ITEM_MAILBOX_TREE_NODE, &decoder);
	if (ret != DSYNC_SLAVE_RECV_RET_OK)
		return ret;

	p_clear(slave->ret_pool);
	node = p_new(slave->ret_pool, struct dsync_mailbox_node, 1);

	value = dsync_deserializer_decode_get(decoder, "name");
	if (*value == '\0') {
		dsync_slave_input_error(slave, decoder, "Empty name");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	*name_r = (void *)p_strsplit_tabescaped(slave->ret_pool, value);

	value = dsync_deserializer_decode_get(decoder, "existence");
	switch (*value) {
	case 'n':
		node->existence = DSYNC_MAILBOX_NODE_NONEXISTENT;
		break;
	case 'y':
		node->existence = DSYNC_MAILBOX_NODE_EXISTS;
		break;
	case 'd':
		node->existence = DSYNC_MAILBOX_NODE_DELETED;
		break;
	}

	if (dsync_deserializer_decode_try(decoder, "mailbox_guid", &value) &&
	    guid_128_from_string(value, node->mailbox_guid) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid mailbox_guid");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "uid_validity", &value) &&
	    str_to_uint32(value, &node->uid_validity) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid uid_validity");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "last_renamed", &value) &&
	    str_to_time(value, &node->last_renamed) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid last_renamed");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "last_subscription_change", &value) &&
	    str_to_time(value, &node->last_subscription_change) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid last_subscription_change");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "subscribed", &value))
		node->subscribed = TRUE;

	*node_r = node;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_io_send_mailbox_deletes(struct dsync_slave *_slave,
				    const struct dsync_mailbox_delete *deletes,
				    unsigned int count, char hierarchy_sep)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_serializer_encoder *encoder;
	string_t *str, *guidstr;
	char sep[2];
	unsigned int i;

	str = t_str_new(128);
	str_append_c(str, items[ITEM_MAILBOX_DELETE].chr);

	encoder = dsync_serializer_encode_begin(slave->serializers[ITEM_MAILBOX_DELETE]);
	sep[0] = hierarchy_sep; sep[1] = '\0';
	dsync_serializer_encode_add(encoder, "hierarchy_sep", sep);

	guidstr = t_str_new(128);
	for (i = 0; i < count; i++) {
		if (deletes[i].delete_mailbox) {
			str_append(guidstr, guid_128_to_string(deletes[i].guid));
			str_append_c(guidstr, ' ');
		}
	}
	if (str_len(guidstr) > 0) {
		str_truncate(guidstr, str_len(guidstr)-1);
		dsync_serializer_encode_add(encoder, "mailboxes",
					    str_c(guidstr));
	}

	str_truncate(guidstr, 0);
	for (i = 0; i < count; i++) {
		if (!deletes[i].delete_mailbox) {
			str_append(guidstr, guid_128_to_string(deletes[i].guid));
			str_append_c(guidstr, ' ');
		}
	}
	if (str_len(guidstr) > 0) {
		str_truncate(guidstr, str_len(guidstr)-1);
		dsync_serializer_encode_add(encoder, "dirs", str_c(guidstr));
	}
	dsync_serializer_encode_finish(&encoder, str);
	dsync_slave_io_send_string(slave, str);
}

ARRAY_DEFINE_TYPE(dsync_mailbox_delete, struct dsync_mailbox_delete);
static int
decode_mailbox_deletes(ARRAY_TYPE(dsync_mailbox_delete) *deletes,
		       const char *value, bool delete_mailbox)
{
	struct dsync_mailbox_delete *del;
	const char *const *guid_strings;
	unsigned int i;

	guid_strings = t_strsplit(value, " ");
	for (i = 0; guid_strings[i] != NULL; i++) {
		del = array_append_space(deletes);
		del->delete_mailbox = delete_mailbox;
		if (guid_128_from_string(guid_strings[i], del->guid) < 0)
			return -1;
	}
	return 0;
}

static enum dsync_slave_recv_ret
dsync_slave_io_recv_mailbox_deletes(struct dsync_slave *_slave,
				    const struct dsync_mailbox_delete **deletes_r,
				    unsigned int *count_r, char *hierarchy_sep_r)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_deserializer_decoder *decoder;
	ARRAY_TYPE(dsync_mailbox_delete) deletes;
	const char *value;
	enum dsync_slave_recv_ret ret;

	ret = dsync_slave_io_input_next(slave, ITEM_MAILBOX_DELETE, &decoder);
	if (ret != DSYNC_SLAVE_RECV_RET_OK)
		return ret;

	p_clear(slave->ret_pool);
	p_array_init(&deletes, slave->ret_pool, 16);

	value = dsync_deserializer_decode_get(decoder, "hierarchy_sep");
	if (strlen(value) != 1) {
		dsync_slave_input_error(slave, decoder, "Invalid hierarchy_sep");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	*hierarchy_sep_r = value[0];

	if (dsync_deserializer_decode_try(decoder, "mailboxes", &value) &&
	    decode_mailbox_deletes(&deletes, value, TRUE) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid mailboxes");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "dirs", &value) &&
	    decode_mailbox_deletes(&deletes, value, FALSE) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid dirs");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	*deletes_r = array_get(&deletes, count_r);
	return DSYNC_SLAVE_RECV_RET_OK;
}

static const char *
get_cache_fields(struct dsync_slave_io *slave,
		 const struct dsync_mailbox *dsync_box)
{
	struct dsync_serializer_encoder *encoder;
	string_t *str;
	const struct mailbox_cache_field *cache_fields;
	unsigned int i, count;
	char decision[3];

	cache_fields = array_get(&dsync_box->cache_fields, &count);
	if (count == 0)
		return "";

	str = t_str_new(128);
	for (i = 0; i < count; i++) {
		const struct mailbox_cache_field *field = &cache_fields[i];

		encoder = dsync_serializer_encode_begin(slave->serializers[ITEM_MAILBOX_CACHE_FIELD]);
		dsync_serializer_encode_add(encoder, "name", field->name);

		memset(decision, 0, sizeof(decision));
		switch (field->decision & ~MAIL_CACHE_DECISION_FORCED) {
		case MAIL_CACHE_DECISION_NO:
			decision[0] = 'n';
			break;
		case MAIL_CACHE_DECISION_TEMP:
			decision[0] = 't';
			break;
		case MAIL_CACHE_DECISION_YES:
			decision[0] = 'y';
			break;
		}
		i_assert(decision[0] != '\0');
		if ((field->decision & MAIL_CACHE_DECISION_FORCED) != 0)
			decision[1] = 'F';
		dsync_serializer_encode_add(encoder, "decision", decision);
		if (field->last_used != 0) {
			dsync_serializer_encode_add(encoder, "last_used",
						    dec2str(field->last_used));
		}
		dsync_serializer_encode_finish(&encoder, str);
	}
	if (i > 0) {
		/* remove the trailing LF */
		str_truncate(str, str_len(str)-1);
	}
	return str_c(str);
}

static void
dsync_slave_io_send_mailbox(struct dsync_slave *_slave,
			    const struct dsync_mailbox *dsync_box)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);
	const char *value;

	str_append_c(str, items[ITEM_MAILBOX].chr);
	encoder = dsync_serializer_encode_begin(slave->serializers[ITEM_MAILBOX]);
	dsync_serializer_encode_add(encoder, "mailbox_guid",
				    guid_128_to_string(dsync_box->mailbox_guid));

	if (dsync_box->mailbox_lost)
		dsync_serializer_encode_add(encoder, "mailbox_lost", "");
	dsync_serializer_encode_add(encoder, "uid_validity",
				    dec2str(dsync_box->uid_validity));
	dsync_serializer_encode_add(encoder, "uid_next",
				    dec2str(dsync_box->uid_next));
	dsync_serializer_encode_add(encoder, "messages_count",
				    dec2str(dsync_box->messages_count));
	dsync_serializer_encode_add(encoder, "first_recent_uid",
				    dec2str(dsync_box->first_recent_uid));
	dsync_serializer_encode_add(encoder, "highest_modseq",
				    dec2str(dsync_box->highest_modseq));

	value = get_cache_fields(slave, dsync_box);
	if (value != NULL)
		dsync_serializer_encode_add(encoder, "cache_fields", value);

	dsync_serializer_encode_finish(&encoder, str);
	dsync_slave_io_send_string(slave, str);
}

static int
parse_cache_field(struct dsync_slave_io *slave, struct dsync_mailbox *box,
		  const char *value)
{
	struct dsync_deserializer_decoder *decoder;
	struct mailbox_cache_field field;
	const char *error;
	int ret = 0;

	if (dsync_deserializer_decode_begin(slave->deserializers[ITEM_MAILBOX_CACHE_FIELD],
					    value, &decoder, &error) < 0) {
		dsync_slave_input_error(slave, NULL,
			"cache_field: Invalid input: %s", error);
		return -1;
	}

	memset(&field, 0, sizeof(field));
	value = dsync_deserializer_decode_get(decoder, "name");
	field.name = p_strdup(slave->ret_pool, value);

	value = dsync_deserializer_decode_get(decoder, "decision");
	switch (*value) {
	case 'n':
		field.decision = MAIL_CACHE_DECISION_NO;
		break;
	case 't':
		field.decision = MAIL_CACHE_DECISION_TEMP;
		break;
	case 'y':
		field.decision = MAIL_CACHE_DECISION_YES;
		break;
	default:
		dsync_slave_input_error(slave, decoder, "Invalid decision: %s",
					value);
		ret = -1;
		break;
	}
	if (value[1] == 'F')
		field.decision |= MAIL_CACHE_DECISION_FORCED;

	if (dsync_deserializer_decode_try(decoder, "last_used", &value) &&
	    str_to_time(value, &field.last_used) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid last_used");
		ret = -1;
	}
	array_append(&box->cache_fields, &field, 1);

	dsync_deserializer_decode_finish(&decoder);
	return ret;
}

static enum dsync_slave_recv_ret
dsync_slave_io_recv_mailbox(struct dsync_slave *_slave,
			    const struct dsync_mailbox **dsync_box_r)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	pool_t pool = slave->ret_pool;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_mailbox *box;
	const char *value;
	enum dsync_slave_recv_ret ret;

	p_clear(pool);
	box = p_new(pool, struct dsync_mailbox, 1);

	ret = dsync_slave_io_input_next(slave, ITEM_MAILBOX, &decoder);
	if (ret != DSYNC_SLAVE_RECV_RET_OK)
		return ret;

	value = dsync_deserializer_decode_get(decoder, "mailbox_guid");
	if (guid_128_from_string(value, box->mailbox_guid) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid mailbox_guid");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}

	if (dsync_deserializer_decode_try(decoder, "mailbox_lost", &value))
		box->mailbox_lost = TRUE;
	value = dsync_deserializer_decode_get(decoder, "uid_validity");
	if (str_to_uint32(value, &box->uid_validity) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid uid_validity");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "uid_next");
	if (str_to_uint32(value, &box->uid_next) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid uid_next");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "messages_count");
	if (str_to_uint32(value, &box->messages_count) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid messages_count");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "first_recent_uid");
	if (str_to_uint32(value, &box->first_recent_uid) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid first_recent_uid");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "highest_modseq");
	if (str_to_uint64(value, &box->highest_modseq) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid highest_modseq");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}

	p_array_init(&box->cache_fields, pool, 32);
	if (dsync_deserializer_decode_try(decoder, "cache_fields", &value)) {
		const char *const *fields = t_strsplit(value, "\n");
		for (; *fields != NULL; fields++) {
			if (parse_cache_field(slave, box, *fields) < 0)
				return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
		}
	}

	*dsync_box_r = box;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_io_send_change(struct dsync_slave *_slave,
			   const struct dsync_mail_change *change)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);
	char type[2];

	str_append_c(str, items[ITEM_MAIL_CHANGE].chr);
	encoder = dsync_serializer_encode_begin(slave->serializers[ITEM_MAIL_CHANGE]);

	type[0] = type[1] = '\0';
	switch (change->type) {
	case DSYNC_MAIL_CHANGE_TYPE_SAVE:
		type[0] = 's';
		break;
	case DSYNC_MAIL_CHANGE_TYPE_EXPUNGE:
		type[0] = 'e';
		break;
	case DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE:
		type[0] = 'f';
		break;
	}
	i_assert(type[0] != '\0');
	dsync_serializer_encode_add(encoder, "type", type);
	dsync_serializer_encode_add(encoder, "uid", dec2str(change->uid));
	if (change->guid != NULL)
		dsync_serializer_encode_add(encoder, "guid", change->guid);
	if (change->hdr_hash != NULL) {
		dsync_serializer_encode_add(encoder, "hdr_hash",
					    change->hdr_hash);
	}
	if (change->modseq != 0) {
		dsync_serializer_encode_add(encoder, "modseq",
					    dec2str(change->modseq));
	}
	if (change->save_timestamp != 0) {
		dsync_serializer_encode_add(encoder, "save_timestamp",
					    dec2str(change->save_timestamp));
	}
	if (change->add_flags != 0) {
		dsync_serializer_encode_add(encoder, "add_flags",
			t_strdup_printf("%x", change->add_flags));
	}
	if (change->remove_flags != 0) {
		dsync_serializer_encode_add(encoder, "remove_flags",
			t_strdup_printf("%x", change->remove_flags));
	}
	if (change->final_flags != 0) {
		dsync_serializer_encode_add(encoder, "final_flags",
			t_strdup_printf("%x", change->final_flags));
	}
	if (change->keywords_reset)
		dsync_serializer_encode_add(encoder, "keywords_reset", "");

	if (array_is_created(&change->keyword_changes) &&
	    array_count(&change->keyword_changes) > 0) {
		string_t *kw_str = t_str_new(128);
		const char *const *changes;
		unsigned int i, count;

		changes = array_get(&change->keyword_changes, &count);
		str_tabescape_write(kw_str, changes[0]);
		for (i = 1; i < count; i++) {
			str_append_c(kw_str, '\t');
			str_tabescape_write(kw_str, changes[i]);
		}
		dsync_serializer_encode_add(encoder, "keyword_changes",
					    str_c(kw_str));
	}

	dsync_serializer_encode_finish(&encoder, str);
	dsync_slave_io_send_string(slave, str);
}

static enum dsync_slave_recv_ret
dsync_slave_io_recv_change(struct dsync_slave *_slave,
			   const struct dsync_mail_change **change_r)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	pool_t pool = slave->ret_pool;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_mail_change *change;
	const char *value;
	enum dsync_slave_recv_ret ret;

	p_clear(pool);
	change = p_new(pool, struct dsync_mail_change, 1);

	ret = dsync_slave_io_input_next(slave, ITEM_MAIL_CHANGE, &decoder);
	if (ret != DSYNC_SLAVE_RECV_RET_OK)
		return ret;

	value = dsync_deserializer_decode_get(decoder, "type");
	switch (*value) {
	case 's':
		change->type = DSYNC_MAIL_CHANGE_TYPE_SAVE;
		break;
	case 'e':
		change->type = DSYNC_MAIL_CHANGE_TYPE_EXPUNGE;
		break;
	case 'f':
		change->type = DSYNC_MAIL_CHANGE_TYPE_FLAG_CHANGE;
		break;
	default:
		dsync_slave_input_error(slave, decoder,
					"Invalid type: %s", value);
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}

	value = dsync_deserializer_decode_get(decoder, "uid");
	if (str_to_uint32(value, &change->uid) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid uid");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}

	if (dsync_deserializer_decode_try(decoder, "guid", &value))
		change->guid = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "hdr_hash", &value))
		change->hdr_hash = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "modseq", &value) &&
	    str_to_uint64(value, &change->modseq) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid modseq");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "save_timestamp", &value) &&
	    str_to_time(value, &change->save_timestamp) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid save_timestamp");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}

	if (dsync_deserializer_decode_try(decoder, "add_flags", &value))
		change->add_flags = strtoul(value, NULL, 16);
	if (dsync_deserializer_decode_try(decoder, "remove_flags", &value))
		change->remove_flags = strtoul(value, NULL, 16);
	if (dsync_deserializer_decode_try(decoder, "final_flags", &value))
		change->final_flags = strtoul(value, NULL, 16);
	if (dsync_deserializer_decode_try(decoder, "keywords_reset", &value))
		change->keywords_reset = TRUE;

	if (dsync_deserializer_decode_try(decoder, "keyword_changes", &value) &&
	    *value != '\0') {
		const char *const *changes = t_strsplit_tab(value);
		unsigned int i, count = str_array_length(changes);

		p_array_init(&change->keyword_changes, pool, count);
		for (i = 0; i < count; i++) {
			value = p_strdup(pool, changes[i]);
			array_append(&change->keyword_changes, &value, 1);
		}
	}

	*change_r = change;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_io_send_mail_request(struct dsync_slave *_slave,
				 const struct dsync_mail_request *request)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);

	str_append_c(str, items[ITEM_MAIL_REQUEST].chr);
	encoder = dsync_serializer_encode_begin(slave->serializers[ITEM_MAIL_REQUEST]);
	if (request->guid != NULL)
		dsync_serializer_encode_add(encoder, "guid", request->guid);
	if (request->uid != 0) {
		dsync_serializer_encode_add(encoder, "uid",
					    dec2str(request->uid));
	}
	dsync_serializer_encode_finish(&encoder, str);
	dsync_slave_io_send_string(slave, str);
}

static enum dsync_slave_recv_ret
dsync_slave_io_recv_mail_request(struct dsync_slave *_slave,
				 const struct dsync_mail_request **request_r)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_mail_request *request;
	const char *value;
	enum dsync_slave_recv_ret ret;

	p_clear(slave->ret_pool);
	request = p_new(slave->ret_pool, struct dsync_mail_request, 1);

	ret = dsync_slave_io_input_next(slave, ITEM_MAIL_REQUEST, &decoder);
	if (ret != DSYNC_SLAVE_RECV_RET_OK)
		return ret;

	if (dsync_deserializer_decode_try(decoder, "guid", &value))
		request->guid = p_strdup(slave->ret_pool, value);
	if (dsync_deserializer_decode_try(decoder, "uid", &value) &&
	    str_to_uint32(value, &request->uid) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid uid");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}

	*request_r = request;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void
dsync_slave_io_send_mail(struct dsync_slave *_slave,
			 const struct dsync_mail *mail)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);

	i_assert(slave->mail_output == NULL);

	str_append_c(str, items[ITEM_MAIL].chr);
	encoder = dsync_serializer_encode_begin(slave->serializers[ITEM_MAIL]);
	if (mail->guid != NULL)
		dsync_serializer_encode_add(encoder, "guid", mail->guid);
	if (mail->uid != 0)
		dsync_serializer_encode_add(encoder, "uid", dec2str(mail->uid));
	if (mail->pop3_uidl != NULL) {
		dsync_serializer_encode_add(encoder, "pop3_uidl",
					    mail->pop3_uidl);
	}
	if (mail->pop3_order > 0) {
		dsync_serializer_encode_add(encoder, "pop3_order",
					    dec2str(mail->pop3_order));
	}
	if (mail->received_date > 0) {
		dsync_serializer_encode_add(encoder, "received_date",
					    dec2str(mail->received_date));
	}
	if (mail->input != NULL)
		dsync_serializer_encode_add(encoder, "stream", "");

	dsync_serializer_encode_finish(&encoder, str);
	dsync_slave_io_send_string(slave, str);

	if (mail->input != NULL) {
		slave->mail_output_last = '\0';
		slave->mail_output = mail->input;
		i_stream_ref(slave->mail_output);
		(void)dsync_slave_io_send_mail_stream(slave);
	}
}

static int seekable_fd_callback(const char **path_r, void *context)
{
	struct dsync_slave_io *slave = context;
	string_t *path;
	int fd;

	path = t_str_new(128);
	str_append(path, slave->temp_path_prefix);
	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		i_error("safe_mkstemp(%s) failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_error("unlink(%s) failed: %m", str_c(path));
		close_keep_errno(fd);
		return -1;
	}

	*path_r = str_c(path);
	return fd;
}

static enum dsync_slave_recv_ret
dsync_slave_io_recv_mail(struct dsync_slave *_slave,
			 struct dsync_mail **mail_r)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	pool_t pool = slave->ret_pool;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_mail *mail;
	struct istream *inputs[2];
	const char *value;
	enum dsync_slave_recv_ret ret;

	if (slave->mail_input != NULL) {
		/* wait until the mail's stream has been read */
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	if (slave->cur_mail != NULL) {
		/* finished reading the stream, return the mail now */
		*mail_r = slave->cur_mail;
		slave->cur_mail = NULL;
		return DSYNC_SLAVE_RECV_RET_OK;
	}

	p_clear(pool);
	mail = p_new(pool, struct dsync_mail, 1);

	ret = dsync_slave_io_input_next(slave, ITEM_MAIL, &decoder);
	if (ret != DSYNC_SLAVE_RECV_RET_OK)
		return ret;

	if (dsync_deserializer_decode_try(decoder, "guid", &value))
		mail->guid = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "uid", &value) &&
	    str_to_uint32(value, &mail->uid) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid uid");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "pop3_uidl", &value))
		mail->pop3_uidl = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "pop3_order", &value) &&
	    str_to_uint(value, &mail->pop3_order) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid pop3_order");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "received_date", &value) &&
	    str_to_time(value, &mail->received_date) < 0) {
		dsync_slave_input_error(slave, decoder, "Invalid received_date");
		return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "stream", &value)) {
		inputs[0] = i_stream_create_dot(slave->input, FALSE);
		inputs[1] = NULL;
		mail->input = i_stream_create_seekable(inputs,
			MAIL_READ_FULL_BLOCK_SIZE, seekable_fd_callback, slave);
		i_stream_unref(&inputs[0]);

		slave->mail_input = mail->input;
		if (dsync_slave_io_read_mail_stream(slave) <= 0) {
			slave->cur_mail = mail;
			return DSYNC_SLAVE_RECV_RET_TRYAGAIN;
		}
		/* already finished reading the stream */
		i_assert(slave->mail_input == NULL);
	}

	*mail_r = mail;
	return DSYNC_SLAVE_RECV_RET_OK;
}

static void dsync_slave_io_flush(struct dsync_slave *_slave)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;

	o_stream_uncork(slave->output);
	o_stream_cork(slave->output);
}

static bool dsync_slave_io_is_send_queue_full(struct dsync_slave *_slave)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;
	size_t bytes;

	if (slave->mail_output != NULL)
		return TRUE;

	bytes = o_stream_get_buffer_used_size(slave->output);
	if (bytes < DSYNC_SLAVE_IO_OUTBUF_THROTTLE_SIZE)
		return FALSE;

	o_stream_set_flush_pending(slave->output, TRUE);
	return TRUE;
}

static bool dsync_slave_io_has_pending_data(struct dsync_slave *_slave)
{
	struct dsync_slave_io *slave = (struct dsync_slave_io *)_slave;

	return slave->has_pending_data;
}

static const struct dsync_slave_vfuncs dsync_slave_io_vfuncs = {
	dsync_slave_io_deinit,
	dsync_slave_io_send_handshake,
	dsync_slave_io_recv_handshake,
	dsync_slave_io_send_end_of_list,
	dsync_slave_io_send_mailbox_state,
	dsync_slave_io_recv_mailbox_state,
	dsync_slave_io_send_mailbox_tree_node,
	dsync_slave_io_recv_mailbox_tree_node,
	dsync_slave_io_send_mailbox_deletes,
	dsync_slave_io_recv_mailbox_deletes,
	dsync_slave_io_send_mailbox,
	dsync_slave_io_recv_mailbox,
	dsync_slave_io_send_change,
	dsync_slave_io_recv_change,
	dsync_slave_io_send_mail_request,
	dsync_slave_io_recv_mail_request,
	dsync_slave_io_send_mail,
	dsync_slave_io_recv_mail,
	dsync_slave_io_flush,
	dsync_slave_io_is_send_queue_full,
	dsync_slave_io_has_pending_data
};

struct dsync_slave *
dsync_slave_init_io(int fd_in, int fd_out, const char *name,
		    const char *temp_path_prefix)
{
	struct dsync_slave_io *slave;

	slave = i_new(struct dsync_slave_io, 1);
	slave->slave.v = dsync_slave_io_vfuncs;
	slave->fd_in = fd_in;
	slave->fd_out = fd_out;
	slave->name = i_strdup(name);
	slave->temp_path_prefix = i_strdup(temp_path_prefix);
	slave->ret_pool = pool_alloconly_create("slave io data", 2048);
	dsync_slave_io_init(slave);
	return &slave->slave;
}
