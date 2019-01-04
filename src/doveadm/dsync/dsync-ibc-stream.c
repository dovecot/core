/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
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
#include "dsync-ibc-private.h"


#define DSYNC_IBC_STREAM_OUTBUF_THROTTLE_SIZE (1024*128)

#define DSYNC_PROTOCOL_VERSION_MAJOR 3
#define DSYNC_PROTOCOL_VERSION_MINOR 5
#define DSYNC_HANDSHAKE_VERSION "VERSION\tdsync\t3\t5\n"

#define DSYNC_PROTOCOL_MINOR_HAVE_ATTRIBUTES 1
#define DSYNC_PROTOCOL_MINOR_HAVE_SAVE_GUID 2
#define DSYNC_PROTOCOL_MINOR_HAVE_FINISH 3
#define DSYNC_PROTOCOL_MINOR_HAVE_HDR_HASH_V2 4
#define DSYNC_PROTOCOL_MINOR_HAVE_HDR_HASH_V3 5

enum item_type {
	ITEM_NONE,
	ITEM_DONE,

	ITEM_HANDSHAKE,
	ITEM_MAILBOX_STATE,
	ITEM_MAILBOX_TREE_NODE,
	ITEM_MAILBOX_DELETE,
	ITEM_MAILBOX,

	ITEM_MAILBOX_ATTRIBUTE,
	ITEM_MAIL_CHANGE,
	ITEM_MAIL_REQUEST,
	ITEM_MAIL,
	ITEM_FINISH,

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
	unsigned int min_minor_version;
} items[ITEM_END_OF_LIST+1] = {
	{ NULL, '\0', NULL, NULL, 0 },
	{ .name = "done",
	  .chr = 'X',
	  .optional_keys = ""
	},
	{ .name = "handshake",
	  .chr = 'H',
	  .required_keys = "hostname",
	  .optional_keys = "sync_ns_prefix sync_box sync_box_guid sync_type "
	  	"debug sync_visible_namespaces exclude_mailboxes  "
	  	"send_mail_requests backup_send backup_recv lock_timeout "
	  	"no_mail_sync no_mailbox_renames no_backup_overwrite purge_remote "
		"no_notify sync_since_timestamp sync_max_size sync_flags sync_until_timestamp "
		"virtual_all_box empty_hdr_workaround import_commit_msgs_interval "
		"hashed_headers"
	},
	{ .name = "mailbox_state",
	  .chr = 'S',
	  .required_keys = "mailbox_guid last_uidvalidity last_common_uid "
	  	"last_common_modseq last_common_pvt_modseq",
	  .optional_keys = "last_messages_count changes_during_sync"
	},
	{ .name = "mailbox_tree_node",
	  .chr = 'N',
	  .required_keys = "name existence",
	  .optional_keys = "mailbox_guid uid_validity uid_next "
	  	"last_renamed_or_created subscribed last_subscription_change"
	},
	{ .name = "mailbox_delete",
	  .chr = 'D',
	  .required_keys = "hierarchy_sep",
	  .optional_keys = "mailboxes dirs unsubscribes"
	},
	{ .name = "mailbox",
	  .chr = 'B',
	  .required_keys = "mailbox_guid uid_validity uid_next messages_count "
		"first_recent_uid highest_modseq highest_pvt_modseq",
	  .optional_keys = "mailbox_lost mailbox_ignore "
			   "cache_fields have_guids have_save_guids have_only_guid128"
	},
	{ .name = "mailbox_attribute",
	  .chr = 'A',
	  .required_keys = "type key",
	  .optional_keys = "value stream deleted last_change modseq",
	  .min_minor_version = DSYNC_PROTOCOL_MINOR_HAVE_ATTRIBUTES
	},
	{ .name = "mail_change",
	  .chr = 'C',
	  .required_keys = "type uid",
	  .optional_keys = "guid hdr_hash modseq pvt_modseq "
	  	"add_flags remove_flags final_flags "
		"keywords_reset keyword_changes received_timestamp virtual_size"
	},
	{ .name = "mail_request",
	  .chr = 'R',
	  .optional_keys = "guid uid"
	},
	{ .name = "mail",
	  .chr = 'M',
	  .optional_keys = "guid uid pop3_uidl pop3_order received_date saved_date stream"
	},
	{ .name = "finish",
	  .chr = 'F',
	  .optional_keys = "error mail_error require_full_resync",
	  .min_minor_version = DSYNC_PROTOCOL_MINOR_HAVE_FINISH
	},
	{ .name = "mailbox_cache_field",
	  .chr = 'c',
	  .required_keys = "name decision",
	  .optional_keys = "last_used"
	},

	{ "end_of_list", '\0', NULL, NULL, 0 }
};

struct dsync_ibc_stream {
	struct dsync_ibc ibc;

	char *name, *temp_path_prefix;
	unsigned int timeout_secs;
	struct istream *input;
	struct ostream *output;
	struct io *io;
	struct timeout *to;

	unsigned int minor_version;
	struct dsync_serializer *serializers[ITEM_END_OF_LIST];
	struct dsync_deserializer *deserializers[ITEM_END_OF_LIST];

	pool_t ret_pool;
	struct dsync_deserializer_decoder *cur_decoder;

	struct istream *value_output, *value_input;
	struct dsync_mail *cur_mail;
	struct dsync_mailbox_attribute *cur_attr;
	char value_output_last;

	enum item_type last_recv_item, last_sent_item;
	bool last_recv_item_eol:1;
	bool last_sent_item_eol:1;

	bool version_received:1;
	bool handshake_received:1;
	bool has_pending_data:1;
	bool finish_received:1;
	bool done_received:1;
	bool stopped:1;
};

static const char *dsync_ibc_stream_get_state(struct dsync_ibc_stream *ibc)
{
	if (!ibc->version_received)
		return "version not received";
	else if (!ibc->handshake_received)
		return "handshake not received";

	return t_strdup_printf("last sent=%s%s, last recv=%s%s",
			       items[ibc->last_sent_item].name,
			       ibc->last_sent_item_eol ? " (EOL)" : "",
			       items[ibc->last_recv_item].name,
			       ibc->last_recv_item_eol ? " (EOL)" : "");
}

static void dsync_ibc_stream_stop(struct dsync_ibc_stream *ibc)
{
	ibc->stopped = TRUE;
	i_stream_close(ibc->input);
	o_stream_close(ibc->output);
	io_loop_stop(current_ioloop);
}

static int dsync_ibc_stream_read_mail_stream(struct dsync_ibc_stream *ibc)
{
	do {
		i_stream_skip(ibc->value_input,
			      i_stream_get_data_size(ibc->value_input));
	} while (i_stream_read(ibc->value_input) > 0);
	if (ibc->value_input->eof) {
		if (ibc->value_input->stream_errno != 0) {
			i_error("dsync(%s): read(%s) failed: %s (%s)", ibc->name,
				i_stream_get_name(ibc->value_input),
				i_stream_get_error(ibc->value_input),
				dsync_ibc_stream_get_state(ibc));
			dsync_ibc_stream_stop(ibc);
			return -1;
		}
		/* finished reading the mail stream */
		i_assert(ibc->value_input->eof);
		i_stream_seek(ibc->value_input, 0);
		ibc->has_pending_data = TRUE;
		ibc->value_input = NULL;
		return 1;
	}
	return 0;
}

static void dsync_ibc_stream_input(struct dsync_ibc_stream *ibc)
{
	timeout_reset(ibc->to);
	if (ibc->value_input != NULL) {
		if (dsync_ibc_stream_read_mail_stream(ibc) == 0)
			return;
	}
	o_stream_cork(ibc->output);
	ibc->ibc.io_callback(ibc->ibc.io_context);
	o_stream_uncork(ibc->output);
}

static int dsync_ibc_stream_send_value_stream(struct dsync_ibc_stream *ibc)
{
	const unsigned char *data;
	unsigned char add;
	size_t i, size;
	int ret;

	while ((ret = i_stream_read_more(ibc->value_output, &data, &size)) > 0) {
		add = '\0';
		for (i = 0; i < size; i++) {
			if (data[i] == '.' &&
			    ((i == 0 && ibc->value_output_last == '\n') ||
			     (i > 0 && data[i-1] == '\n'))) {
				/* escape the dot */
				add = '.';
				break;
			}
		}

		if (i > 0) {
			o_stream_nsend(ibc->output, data, i);
			ibc->value_output_last = data[i-1];
			i_stream_skip(ibc->value_output, i);
		}

		if (o_stream_get_buffer_used_size(ibc->output) >= 4096) {
			if ((ret = o_stream_flush(ibc->output)) < 0) {
				dsync_ibc_stream_stop(ibc);
				return -1;
			}
			if (ret == 0) {
				/* continue later */
				o_stream_set_flush_pending(ibc->output, TRUE);
				return 0;
			}
		}

		if (add != '\0') {
			o_stream_nsend(ibc->output, &add, 1);
			ibc->value_output_last = add;
		}
	}
	i_assert(ret == -1);

	if (ibc->value_output->stream_errno != 0) {
		i_error("dsync(%s): read(%s) failed: %s (%s)",
			ibc->name, i_stream_get_name(ibc->value_output),
			i_stream_get_error(ibc->value_output),
			dsync_ibc_stream_get_state(ibc));
		dsync_ibc_stream_stop(ibc);
		return -1;
	}

	/* finished sending the stream. use "CRLF." instead of "LF." just in
	   case we're sending binary data that ends with CR. */
	o_stream_nsend_str(ibc->output, "\r\n.\r\n");
	i_stream_unref(&ibc->value_output);
	return 1;
}

static int dsync_ibc_stream_output(struct dsync_ibc_stream *ibc)
{
	struct ostream *output = ibc->output;
	int ret;

	if ((ret = o_stream_flush(output)) < 0)
		ret = 1;
	else if (ibc->value_output != NULL) {
		if (dsync_ibc_stream_send_value_stream(ibc) < 0)
			ret = 1;
	}
	timeout_reset(ibc->to);

	if (!dsync_ibc_is_send_queue_full(&ibc->ibc))
		ibc->ibc.io_callback(ibc->ibc.io_context);
	return ret;
}

static void dsync_ibc_stream_timeout(struct dsync_ibc_stream *ibc)
{
	i_error("dsync(%s): I/O has stalled, no activity for %u seconds (%s)",
		ibc->name, ibc->timeout_secs, dsync_ibc_stream_get_state(ibc));
	ibc->ibc.timeout = TRUE;
	dsync_ibc_stream_stop(ibc);
}

static void dsync_ibc_stream_init(struct dsync_ibc_stream *ibc)
{
	unsigned int i;

	ibc->io = io_add_istream(ibc->input, dsync_ibc_stream_input, ibc);
	o_stream_set_no_error_handling(ibc->output, TRUE);
	o_stream_set_flush_callback(ibc->output, dsync_ibc_stream_output, ibc);
	ibc->to = timeout_add(ibc->timeout_secs * 1000,
			      dsync_ibc_stream_timeout, ibc);
	o_stream_cork(ibc->output);
	o_stream_nsend_str(ibc->output, DSYNC_HANDSHAKE_VERSION);

	/* initialize serializers and send their headers to remote */
	for (i = ITEM_DONE + 1; i < ITEM_END_OF_LIST; i++) T_BEGIN {
		const char *keys;

		keys = items[i].required_keys == NULL ? items[i].optional_keys :
			t_strconcat(items[i].required_keys, " ",
				    items[i].optional_keys, NULL);
		if (keys != NULL) {
			i_assert(items[i].chr != '\0');

			ibc->serializers[i] =
				dsync_serializer_init(t_strsplit_spaces(keys, " "));
			o_stream_nsend(ibc->output, &items[i].chr, 1);
			o_stream_nsend_str(ibc->output,
				dsync_serializer_encode_header_line(ibc->serializers[i]));
		}
	} T_END;
	o_stream_nsend_str(ibc->output, ".\n");
	o_stream_uncork(ibc->output);
}

static void dsync_ibc_stream_deinit(struct dsync_ibc *_ibc)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	unsigned int i;

	for (i = ITEM_DONE + 1; i < ITEM_END_OF_LIST; i++) {
		if (ibc->serializers[i] != NULL)
			dsync_serializer_deinit(&ibc->serializers[i]);
		if (ibc->deserializers[i] != NULL)
			dsync_deserializer_deinit(&ibc->deserializers[i]);
	}
	if (ibc->cur_decoder != NULL)
		dsync_deserializer_decode_finish(&ibc->cur_decoder);
	if (ibc->value_output != NULL)
		i_stream_unref(&ibc->value_output);
	else {
		/* If the remote has not told us that they are closing we
		   notify remote that we're closing. this is mainly to avoid
		   "read() failed: EOF" errors on failing dsyncs.

		   Avoid a race condition:
		   We do not tell the remote we are closing if they have
		   already told us because they close the
		   connection after sending ITEM_DONE and will
		   not be ever receive anything else from us unless
		   it just happens to get combined into the same packet
		   as a previous response and is already in the buffer.
		*/
		if (!ibc->done_received && !ibc->finish_received) {
			o_stream_nsend_str(ibc->output,
				t_strdup_printf("%c\n", items[ITEM_DONE].chr));
		}
		(void)o_stream_finish(ibc->output);
	}

	timeout_remove(&ibc->to);
	io_remove(&ibc->io);
	i_stream_destroy(&ibc->input);
	o_stream_destroy(&ibc->output);
	pool_unref(&ibc->ret_pool);
	i_free(ibc->temp_path_prefix);
	i_free(ibc->name);
	i_free(ibc);
}

static int dsync_ibc_stream_next_line(struct dsync_ibc_stream *ibc,
				      const char **line_r)
{
	string_t *error;
	const char *line;
	ssize_t ret;

	line = i_stream_next_line(ibc->input);
	if (line != NULL) {
		*line_r = line;
		return 1;
	}
	/* try reading some */
	if ((ret = i_stream_read(ibc->input)) == -1) {
		if (ibc->stopped)
			return -1;
		error = t_str_new(128);
		if (ibc->input->stream_errno != 0) {
			str_printfa(error, "read(%s) failed: %s", ibc->name,
				    i_stream_get_error(ibc->input));
		} else {
			i_assert(ibc->input->eof);
			str_printfa(error, "read(%s) failed: EOF", ibc->name);
		}
		str_printfa(error, " (%s)", dsync_ibc_stream_get_state(ibc));
		i_error("%s", str_c(error));
		dsync_ibc_stream_stop(ibc);
		return -1;
	}
	i_assert(ret >= 0);
	*line_r = i_stream_next_line(ibc->input);
	if (*line_r == NULL) {
		ibc->has_pending_data = FALSE;
		return 0;
	}
	ibc->has_pending_data = TRUE;
	return 1;
}

static void ATTR_FORMAT(3, 4) ATTR_NULL(2)
dsync_ibc_input_error(struct dsync_ibc_stream *ibc,
		      struct dsync_deserializer_decoder *decoder,
		      const char *fmt, ...)
{
	va_list args;
	const char *error;

	va_start(args, fmt);
	error = t_strdup_vprintf(fmt, args);
	if (decoder == NULL)
		i_error("dsync(%s): %s", ibc->name, error);
	else {
		i_error("dsync(%s): %s: %s", ibc->name,
			dsync_deserializer_decoder_get_name(decoder), error);
	}
	va_end(args);

	dsync_ibc_stream_stop(ibc);
}

static void
dsync_ibc_stream_send_string(struct dsync_ibc_stream *ibc,
			     const string_t *str)
{
	i_assert(ibc->value_output == NULL);
	o_stream_nsend(ibc->output, str_data(str), str_len(str));
}

static int seekable_fd_callback(const char **path_r, void *context)
{
	struct dsync_ibc_stream *ibc = context;
	string_t *path;
	int fd;

	path = t_str_new(128);
	str_append(path, ibc->temp_path_prefix);
	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		i_error("safe_mkstemp(%s) failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (i_unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_close_fd(&fd);
		return -1;
	}

	*path_r = str_c(path);
	return fd;
}

static struct istream *
dsync_ibc_stream_input_stream(struct dsync_ibc_stream *ibc)
{
	struct istream *inputs[2];

	inputs[0] = i_stream_create_dot(ibc->input, FALSE);
	inputs[1] = NULL;
	ibc->value_input = i_stream_create_seekable(inputs, MAIL_READ_FULL_BLOCK_SIZE,
						    seekable_fd_callback, ibc);
	i_stream_unref(&inputs[0]);

	return ibc->value_input;
}

static int
dsync_ibc_check_missing_deserializers(struct dsync_ibc_stream *ibc)
{
	unsigned int i;
	int ret = 0;

	for (i = ITEM_DONE + 1; i < ITEM_END_OF_LIST; i++) {
		if (ibc->deserializers[i] == NULL &&
		    ibc->minor_version >= items[i].min_minor_version &&
		    (items[i].required_keys != NULL ||
		     items[i].optional_keys != NULL)) {
			dsync_ibc_input_error(ibc, NULL,
				"Remote didn't handshake deserializer for %s",
				items[i].name);
			ret = -1;
		}
	}
	return ret;
}

static bool
dsync_ibc_stream_handshake(struct dsync_ibc_stream *ibc, const char *line)
{
	enum item_type item = ITEM_NONE;
	const char *const *required_keys, *error;
	unsigned int i;

	if (ibc->handshake_received)
		return TRUE;

	if (!ibc->version_received) {
		if (!version_string_verify_full(line, "dsync",
						DSYNC_PROTOCOL_VERSION_MAJOR,
						&ibc->minor_version)) {
			dsync_ibc_input_error(ibc, NULL,
				"Remote dsync doesn't use compatible protocol");
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
		ibc->version_received = TRUE;
		return FALSE;
	}

	if (strcmp(line, END_OF_LIST_LINE) == 0) {
		/* finished handshaking */
		if (dsync_ibc_check_missing_deserializers(ibc) < 0)
			return FALSE;
		ibc->handshake_received = TRUE;
		ibc->last_recv_item = ITEM_HANDSHAKE;
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
				    &ibc->deserializers[item], &error) < 0) {
		dsync_ibc_input_error(ibc, NULL,
			"Remote sent invalid handshake for %s: %s",
			items[item].name, error);
	}
	return FALSE;
}

static enum dsync_ibc_recv_ret
dsync_ibc_stream_input_next(struct dsync_ibc_stream *ibc, enum item_type item,
			    struct dsync_deserializer_decoder **decoder_r)
{
	enum item_type line_item = ITEM_NONE;
	const char *line, *error;
	unsigned int i;

	i_assert(ibc->value_input == NULL);

	timeout_reset(ibc->to);

	do {
		if (dsync_ibc_stream_next_line(ibc, &line) <= 0)
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
	} while (!dsync_ibc_stream_handshake(ibc, line));

	ibc->last_recv_item = item;
	ibc->last_recv_item_eol = FALSE;

	if (strcmp(line, END_OF_LIST_LINE) == 0) {
		/* end of this list */
		ibc->last_recv_item_eol = TRUE;
		return DSYNC_IBC_RECV_RET_FINISHED;
	}
	if (line[0] == items[ITEM_DONE].chr) {
		/* remote cleanly closed the connection, possibly because of
		   some failure (which it should have logged). we don't want to
		   log any stream errors anyway after this. */
		ibc->done_received = TRUE;
		dsync_ibc_stream_stop(ibc);
		return DSYNC_IBC_RECV_RET_TRYAGAIN;

	}
	for (i = 1; i < ITEM_END_OF_LIST; i++) {
		if (*line == items[i].chr) {
			line_item = i;
			break;
		}
	}
	if (line_item != item) {
		dsync_ibc_input_error(ibc, NULL,
			"Received unexpected input %c != %c",
			*line, items[item].chr);
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}

	if (ibc->cur_decoder != NULL)
		dsync_deserializer_decode_finish(&ibc->cur_decoder);
	if (dsync_deserializer_decode_begin(ibc->deserializers[item],
					    line+1, &ibc->cur_decoder,
					    &error) < 0) {
		dsync_ibc_input_error(ibc, NULL, "Invalid input to %s: %s",
				      items[item].name, error);
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	*decoder_r = ibc->cur_decoder;
	return DSYNC_IBC_RECV_RET_OK;
}

static struct dsync_serializer_encoder *
dsync_ibc_send_encode_begin(struct dsync_ibc_stream *ibc, enum item_type item)
{
	ibc->last_sent_item = item;
	ibc->last_sent_item_eol = FALSE;
	return dsync_serializer_encode_begin(ibc->serializers[item]);
}

static void
dsync_ibc_stream_send_handshake(struct dsync_ibc *_ibc,
				const struct dsync_ibc_settings *set)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);
	char sync_type[2];

	str_append_c(str, items[ITEM_HANDSHAKE].chr);
	encoder = dsync_ibc_send_encode_begin(ibc, ITEM_HANDSHAKE);
	dsync_serializer_encode_add(encoder, "hostname", set->hostname);
	if (set->sync_ns_prefixes != NULL) {
		dsync_serializer_encode_add(encoder, "sync_ns_prefix",
					    set->sync_ns_prefixes);
	}
	if (set->sync_box != NULL)
		dsync_serializer_encode_add(encoder, "sync_box", set->sync_box);
	if (set->virtual_all_box != NULL) {
		dsync_serializer_encode_add(encoder, "virtual_all_box",
					    set->virtual_all_box);
	}
	if (set->exclude_mailboxes != NULL) {
		string_t *substr = t_str_new(64);
		unsigned int i;

		for (i = 0; set->exclude_mailboxes[i] != NULL; i++) {
			if (i != 0)
				str_append_c(substr, '\t');
			str_append_tabescaped(substr, set->exclude_mailboxes[i]);
		}
		dsync_serializer_encode_add(encoder, "exclude_mailboxes",
					    str_c(substr));
	}
	if (!guid_128_is_empty(set->sync_box_guid)) {
		dsync_serializer_encode_add(encoder, "sync_box_guid",
			guid_128_to_string(set->sync_box_guid));
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
	if (sync_type[0] != '\0')
		dsync_serializer_encode_add(encoder, "sync_type", sync_type);
	if (set->lock_timeout > 0) {
		dsync_serializer_encode_add(encoder, "lock_timeout",
			t_strdup_printf("%u", set->lock_timeout));
	}
	if (set->import_commit_msgs_interval > 0) {
		dsync_serializer_encode_add(encoder, "import_commit_msgs_interval",
			t_strdup_printf("%u", set->import_commit_msgs_interval));
	}
	if (set->sync_since_timestamp > 0) {
		dsync_serializer_encode_add(encoder, "sync_since_timestamp",
			t_strdup_printf("%ld", (long)set->sync_since_timestamp));
	}
	if (set->sync_until_timestamp > 0) {
		dsync_serializer_encode_add(encoder, "sync_until_timestamp",
			t_strdup_printf("%ld", (long)set->sync_since_timestamp));
	}
	if (set->sync_max_size > 0) {
		dsync_serializer_encode_add(encoder, "sync_max_size",
			t_strdup_printf("%"PRIu64, set->sync_max_size));
	}
	if (set->sync_flags != NULL) {
		dsync_serializer_encode_add(encoder, "sync_flags",
					    set->sync_flags);
	}
	if ((set->brain_flags & DSYNC_BRAIN_FLAG_SEND_MAIL_REQUESTS) != 0)
		dsync_serializer_encode_add(encoder, "send_mail_requests", "");
	if ((set->brain_flags & DSYNC_BRAIN_FLAG_BACKUP_SEND) != 0)
		dsync_serializer_encode_add(encoder, "backup_send", "");
	if ((set->brain_flags & DSYNC_BRAIN_FLAG_BACKUP_RECV) != 0)
		dsync_serializer_encode_add(encoder, "backup_recv", "");
	if ((set->brain_flags & DSYNC_BRAIN_FLAG_DEBUG) != 0)
		dsync_serializer_encode_add(encoder, "debug", "");
	if ((set->brain_flags & DSYNC_BRAIN_FLAG_SYNC_VISIBLE_NAMESPACES) != 0)
		dsync_serializer_encode_add(encoder, "sync_visible_namespaces", "");
	if ((set->brain_flags & DSYNC_BRAIN_FLAG_NO_MAIL_SYNC) != 0)
		dsync_serializer_encode_add(encoder, "no_mail_sync", "");
	if ((set->brain_flags & DSYNC_BRAIN_FLAG_NO_MAILBOX_RENAMES) != 0)
		dsync_serializer_encode_add(encoder, "no_mailbox_renames", "");
	if ((set->brain_flags & DSYNC_BRAIN_FLAG_NO_BACKUP_OVERWRITE) != 0)
		dsync_serializer_encode_add(encoder, "no_backup_overwrite", "");
	if ((set->brain_flags & DSYNC_BRAIN_FLAG_PURGE_REMOTE) != 0)
		dsync_serializer_encode_add(encoder, "purge_remote", "");
	if ((set->brain_flags & DSYNC_BRAIN_FLAG_NO_NOTIFY) != 0)
		dsync_serializer_encode_add(encoder, "no_notify", "");
	if ((set->brain_flags & DSYNC_BRAIN_FLAG_EMPTY_HDR_WORKAROUND) != 0)
		dsync_serializer_encode_add(encoder, "empty_hdr_workaround", "");
	/* this can be NULL in slave */
	string_t *str2 = t_str_new(32);
	if (set->hashed_headers != NULL) {
		for(const char *const *ptr = set->hashed_headers; *ptr != NULL; ptr++) {
			str_append_tabescaped(str2, *ptr);
			str_append_c(str2, '\t');
		}
	}
	dsync_serializer_encode_add(encoder, "hashed_headers", str_c(str2));
	dsync_serializer_encode_finish(&encoder, str);
	dsync_ibc_stream_send_string(ibc, str);
}

static enum dsync_ibc_recv_ret
dsync_ibc_stream_recv_handshake(struct dsync_ibc *_ibc,
				const struct dsync_ibc_settings **set_r)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_ibc_settings *set;
	const char *value;
	pool_t pool = ibc->ret_pool;
	enum dsync_ibc_recv_ret ret;

	ret = dsync_ibc_stream_input_next(ibc, ITEM_HANDSHAKE, &decoder);
	if (ret != DSYNC_IBC_RECV_RET_OK) {
		if (ret != DSYNC_IBC_RECV_RET_TRYAGAIN) {
			i_error("dsync(%s): Unexpected input in handshake",
				ibc->name);
			dsync_ibc_stream_stop(ibc);
		}
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}

	p_clear(pool);
	set = p_new(pool, struct dsync_ibc_settings, 1);

	value = dsync_deserializer_decode_get(decoder, "hostname");
	set->hostname = p_strdup(pool, value);
	/* now that we know the remote's hostname, use it for the
	   stream's name */
	i_free(ibc->name);
	ibc->name = i_strdup(set->hostname);

	if (dsync_deserializer_decode_try(decoder, "sync_ns_prefix", &value))
		set->sync_ns_prefixes = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "sync_box", &value))
		set->sync_box = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "virtual_all_box", &value))
		set->virtual_all_box = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "sync_box_guid", &value) &&
	    guid_128_from_string(value, set->sync_box_guid) < 0) {
		dsync_ibc_input_error(ibc, decoder,
				      "Invalid sync_box_guid: %s", value);
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "exclude_mailboxes", &value) &&
	    *value != '\0') {
		char **boxes = p_strsplit_tabescaped(pool, value);
		set->exclude_mailboxes = (const void *)boxes;
	}
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
			dsync_ibc_input_error(ibc, decoder,
				"Unknown sync_type: %s", value);
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
	}
	if (dsync_deserializer_decode_try(decoder, "lock_timeout", &value)) {
		if (str_to_uint(value, &set->lock_timeout) < 0 ||
		    set->lock_timeout == 0) {
			dsync_ibc_input_error(ibc, decoder,
				"Invalid lock_timeout: %s", value);
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
	}
	if (dsync_deserializer_decode_try(decoder, "import_commit_msgs_interval", &value)) {
		if (str_to_uint(value, &set->import_commit_msgs_interval) < 0 ||
		    set->import_commit_msgs_interval == 0) {
			dsync_ibc_input_error(ibc, decoder,
				"Invalid import_commit_msgs_interval: %s", value);
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
	}
	if (dsync_deserializer_decode_try(decoder, "sync_since_timestamp", &value)) {
		if (str_to_time(value, &set->sync_since_timestamp) < 0 ||
		    set->sync_since_timestamp == 0) {
			dsync_ibc_input_error(ibc, decoder,
				"Invalid sync_since_timestamp: %s", value);
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
	}
	if (dsync_deserializer_decode_try(decoder, "sync_until_timestamp", &value)) {
		if (str_to_time(value, &set->sync_until_timestamp) < 0 ||
		    set->sync_until_timestamp == 0) {
			dsync_ibc_input_error(ibc, decoder,
				"Invalid sync_until_timestamp: %s", value);
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
	}
	if (dsync_deserializer_decode_try(decoder, "sync_max_size", &value)) {
		if (str_to_uoff(value, &set->sync_max_size) < 0 ||
		    set->sync_max_size == 0) {
			dsync_ibc_input_error(ibc, decoder,
				"Invalid sync_max_size: %s", value);
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
	}
	if (dsync_deserializer_decode_try(decoder, "sync_flags", &value))
		set->sync_flags = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "send_mail_requests", &value))
		set->brain_flags |= DSYNC_BRAIN_FLAG_SEND_MAIL_REQUESTS;
	if (dsync_deserializer_decode_try(decoder, "backup_send", &value))
		set->brain_flags |= DSYNC_BRAIN_FLAG_BACKUP_SEND;
	if (dsync_deserializer_decode_try(decoder, "backup_recv", &value))
		set->brain_flags |= DSYNC_BRAIN_FLAG_BACKUP_RECV;
	if (dsync_deserializer_decode_try(decoder, "debug", &value))
		set->brain_flags |= DSYNC_BRAIN_FLAG_DEBUG;
	if (dsync_deserializer_decode_try(decoder, "sync_visible_namespaces", &value))
		set->brain_flags |= DSYNC_BRAIN_FLAG_SYNC_VISIBLE_NAMESPACES;
	if (dsync_deserializer_decode_try(decoder, "no_mail_sync", &value))
		set->brain_flags |= DSYNC_BRAIN_FLAG_NO_MAIL_SYNC;
	if (dsync_deserializer_decode_try(decoder, "no_mailbox_renames", &value))
		set->brain_flags |= DSYNC_BRAIN_FLAG_NO_MAILBOX_RENAMES;
	if (dsync_deserializer_decode_try(decoder, "no_backup_overwrite", &value))
		set->brain_flags |= DSYNC_BRAIN_FLAG_NO_BACKUP_OVERWRITE;
	if (dsync_deserializer_decode_try(decoder, "purge_remote", &value))
		set->brain_flags |= DSYNC_BRAIN_FLAG_PURGE_REMOTE;
	if (dsync_deserializer_decode_try(decoder, "no_notify", &value))
		set->brain_flags |= DSYNC_BRAIN_FLAG_NO_NOTIFY;
	if (dsync_deserializer_decode_try(decoder, "empty_hdr_workaround", &value))
		set->brain_flags |= DSYNC_BRAIN_FLAG_EMPTY_HDR_WORKAROUND;
	if (dsync_deserializer_decode_try(decoder, "hashed_headers", &value))
		set->hashed_headers = (const char*const*)p_strsplit_tabescaped(pool, value);
	set->hdr_hash_v2 = ibc->minor_version >= DSYNC_PROTOCOL_MINOR_HAVE_HDR_HASH_V2;
	set->hdr_hash_v3 = ibc->minor_version >= DSYNC_PROTOCOL_MINOR_HAVE_HDR_HASH_V3;

	*set_r = set;
	return DSYNC_IBC_RECV_RET_OK;
}

static void
dsync_ibc_stream_send_end_of_list(struct dsync_ibc *_ibc,
				  enum dsync_ibc_eol_type type)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;

	i_assert(ibc->value_output == NULL);

	switch (type) {
	case DSYNC_IBC_EOL_MAILBOX_ATTRIBUTE:
		if (ibc->minor_version < DSYNC_PROTOCOL_MINOR_HAVE_ATTRIBUTES)
			return;
		break;
	default:
		break;
	}

	ibc->last_sent_item_eol = TRUE;
	o_stream_nsend_str(ibc->output, END_OF_LIST_LINE"\n");
}

static void
dsync_ibc_stream_send_mailbox_state(struct dsync_ibc *_ibc,
				    const struct dsync_mailbox_state *state)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);

	str_append_c(str, items[ITEM_MAILBOX_STATE].chr);
	encoder = dsync_ibc_send_encode_begin(ibc, ITEM_MAILBOX_STATE);
	dsync_serializer_encode_add(encoder, "mailbox_guid",
				    guid_128_to_string(state->mailbox_guid));
	dsync_serializer_encode_add(encoder, "last_uidvalidity",
				    dec2str(state->last_uidvalidity));
	dsync_serializer_encode_add(encoder, "last_common_uid",
				    dec2str(state->last_common_uid));
	dsync_serializer_encode_add(encoder, "last_common_modseq",
				    dec2str(state->last_common_modseq));
	dsync_serializer_encode_add(encoder, "last_common_pvt_modseq",
				    dec2str(state->last_common_pvt_modseq));
	dsync_serializer_encode_add(encoder, "last_messages_count",
				    dec2str(state->last_messages_count));
	if (state->changes_during_sync)
		dsync_serializer_encode_add(encoder, "changes_during_sync", "");

	dsync_serializer_encode_finish(&encoder, str);
	dsync_ibc_stream_send_string(ibc, str);
}

static enum dsync_ibc_recv_ret
dsync_ibc_stream_recv_mailbox_state(struct dsync_ibc *_ibc,
				    struct dsync_mailbox_state *state_r)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_deserializer_decoder *decoder;
	const char *value;
	enum dsync_ibc_recv_ret ret;

	i_zero(state_r);

	ret = dsync_ibc_stream_input_next(ibc, ITEM_MAILBOX_STATE, &decoder);
	if (ret != DSYNC_IBC_RECV_RET_OK)
		return ret;

	value = dsync_deserializer_decode_get(decoder, "mailbox_guid");
	if (guid_128_from_string(value, state_r->mailbox_guid) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid mailbox_guid");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "last_uidvalidity");
	if (str_to_uint32(value, &state_r->last_uidvalidity) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid last_uidvalidity");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "last_common_uid");
	if (str_to_uint32(value, &state_r->last_common_uid) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid last_common_uid");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "last_common_modseq");
	if (str_to_uint64(value, &state_r->last_common_modseq) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid last_common_modseq");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "last_common_pvt_modseq");
	if (str_to_uint64(value, &state_r->last_common_pvt_modseq) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid last_common_pvt_modseq");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "last_messages_count", &value) &&
	    str_to_uint32(value, &state_r->last_messages_count) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid last_messages_count");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "changes_during_sync", &value))
		state_r->changes_during_sync = TRUE;
	return DSYNC_IBC_RECV_RET_OK;
}

static void
dsync_ibc_stream_send_mailbox_tree_node(struct dsync_ibc *_ibc,
					const char *const *name,
					const struct dsync_mailbox_node *node)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
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
		str_append_tabescaped(namestr, *name);
		str_append_c(namestr, '\t');
	}
	str_truncate(namestr, str_len(namestr)-1);

	encoder = dsync_ibc_send_encode_begin(ibc, ITEM_MAILBOX_TREE_NODE);
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
	if (node->uid_next != 0) {
		dsync_serializer_encode_add(encoder, "uid_next",
					    dec2str(node->uid_next));
	}
	if (node->last_renamed_or_created != 0) {
		dsync_serializer_encode_add(encoder, "last_renamed_or_created",
					    dec2str(node->last_renamed_or_created));
	}
	if (node->last_subscription_change != 0) {
		dsync_serializer_encode_add(encoder, "last_subscription_change",
			dec2str(node->last_subscription_change));
	}
	if (node->subscribed)
		dsync_serializer_encode_add(encoder, "subscribed", "");
	dsync_serializer_encode_finish(&encoder, str);
	dsync_ibc_stream_send_string(ibc, str);
}

static enum dsync_ibc_recv_ret
dsync_ibc_stream_recv_mailbox_tree_node(struct dsync_ibc *_ibc,
					const char *const **name_r,
					const struct dsync_mailbox_node **node_r)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_mailbox_node *node;
	const char *value;
	enum dsync_ibc_recv_ret ret;

	ret = dsync_ibc_stream_input_next(ibc, ITEM_MAILBOX_TREE_NODE, &decoder);
	if (ret != DSYNC_IBC_RECV_RET_OK)
		return ret;

	p_clear(ibc->ret_pool);
	node = p_new(ibc->ret_pool, struct dsync_mailbox_node, 1);

	value = dsync_deserializer_decode_get(decoder, "name");
	if (*value == '\0') {
		dsync_ibc_input_error(ibc, decoder, "Empty name");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	*name_r = (void *)p_strsplit_tabescaped(ibc->ret_pool, value);

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
		dsync_ibc_input_error(ibc, decoder, "Invalid mailbox_guid");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "uid_validity", &value) &&
	    str_to_uint32(value, &node->uid_validity) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid uid_validity");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "uid_next", &value) &&
	    str_to_uint32(value, &node->uid_next) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid uid_next");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "last_renamed_or_created", &value) &&
	    str_to_time(value, &node->last_renamed_or_created) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid last_renamed_or_created");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "last_subscription_change", &value) &&
	    str_to_time(value, &node->last_subscription_change) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid last_subscription_change");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "subscribed", &value))
		node->subscribed = TRUE;

	*node_r = node;
	return DSYNC_IBC_RECV_RET_OK;
}

static void
dsync_ibc_stream_encode_delete(string_t *str,
			       struct dsync_serializer_encoder *encoder,
			       const struct dsync_mailbox_delete *deletes,
			       unsigned int count, const char *key,
			       enum dsync_mailbox_delete_type type)
{
	unsigned int i;

	str_truncate(str, 0);
	for (i = 0; i < count; i++) {
		if (deletes[i].type == type) {
			str_append(str, guid_128_to_string(deletes[i].guid));
			str_printfa(str, " %ld ", (long)deletes[i].timestamp);
		}
	}
	if (str_len(str) > 0) {
		str_truncate(str, str_len(str)-1);
		dsync_serializer_encode_add(encoder, key, str_c(str));
	}
}

static void
dsync_ibc_stream_send_mailbox_deletes(struct dsync_ibc *_ibc,
				      const struct dsync_mailbox_delete *deletes,
				      unsigned int count, char hierarchy_sep)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_serializer_encoder *encoder;
	string_t *str, *substr;
	char sep[2];

	str = t_str_new(128);
	str_append_c(str, items[ITEM_MAILBOX_DELETE].chr);

	encoder = dsync_ibc_send_encode_begin(ibc, ITEM_MAILBOX_DELETE);
	sep[0] = hierarchy_sep; sep[1] = '\0';
	dsync_serializer_encode_add(encoder, "hierarchy_sep", sep);

	substr = t_str_new(128);
	dsync_ibc_stream_encode_delete(substr, encoder, deletes, count,
				       "mailboxes",
				       DSYNC_MAILBOX_DELETE_TYPE_MAILBOX);
	dsync_ibc_stream_encode_delete(substr, encoder, deletes, count,
				       "dirs",
				       DSYNC_MAILBOX_DELETE_TYPE_DIR);
	dsync_ibc_stream_encode_delete(substr, encoder, deletes, count,
				       "unsubscribes",
				       DSYNC_MAILBOX_DELETE_TYPE_UNSUBSCRIBE);
	dsync_serializer_encode_finish(&encoder, str);
	dsync_ibc_stream_send_string(ibc, str);
}

ARRAY_DEFINE_TYPE(dsync_mailbox_delete, struct dsync_mailbox_delete);
static int
decode_mailbox_deletes(ARRAY_TYPE(dsync_mailbox_delete) *deletes,
		       const char *value, enum dsync_mailbox_delete_type type)
{
	struct dsync_mailbox_delete *del;
	const char *const *tmp;
	unsigned int i;

	tmp = t_strsplit(value, " ");
	for (i = 0; tmp[i] != NULL; i += 2) {
		del = array_append_space(deletes);
		del->type = type;
		if (guid_128_from_string(tmp[i], del->guid) < 0)
			return -1;
		if (tmp[i+1] == NULL ||
		    str_to_time(tmp[i+1], &del->timestamp) < 0)
			return -1;
	}
	return 0;
}

static enum dsync_ibc_recv_ret
dsync_ibc_stream_recv_mailbox_deletes(struct dsync_ibc *_ibc,
				      const struct dsync_mailbox_delete **deletes_r,
				      unsigned int *count_r, char *hierarchy_sep_r)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_deserializer_decoder *decoder;
	ARRAY_TYPE(dsync_mailbox_delete) deletes;
	const char *value;
	enum dsync_ibc_recv_ret ret;

	ret = dsync_ibc_stream_input_next(ibc, ITEM_MAILBOX_DELETE, &decoder);
	if (ret != DSYNC_IBC_RECV_RET_OK)
		return ret;

	p_clear(ibc->ret_pool);
	p_array_init(&deletes, ibc->ret_pool, 16);

	value = dsync_deserializer_decode_get(decoder, "hierarchy_sep");
	if (strlen(value) != 1) {
		dsync_ibc_input_error(ibc, decoder, "Invalid hierarchy_sep");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	*hierarchy_sep_r = value[0];

	if (dsync_deserializer_decode_try(decoder, "mailboxes", &value) &&
	    decode_mailbox_deletes(&deletes, value,
				   DSYNC_MAILBOX_DELETE_TYPE_MAILBOX) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid mailboxes");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "dirs", &value) &&
	    decode_mailbox_deletes(&deletes, value,
				   DSYNC_MAILBOX_DELETE_TYPE_DIR) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid dirs");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "unsubscribes", &value) &&
	    decode_mailbox_deletes(&deletes, value,
				   DSYNC_MAILBOX_DELETE_TYPE_UNSUBSCRIBE) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid dirs");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	*deletes_r = array_get(&deletes, count_r);
	return DSYNC_IBC_RECV_RET_OK;
}

static const char *
get_cache_fields(struct dsync_ibc_stream *ibc,
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

		encoder = dsync_serializer_encode_begin(ibc->serializers[ITEM_MAILBOX_CACHE_FIELD]);
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
dsync_ibc_stream_send_mailbox(struct dsync_ibc *_ibc,
			      const struct dsync_mailbox *dsync_box)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);
	const char *value;

	str_append_c(str, items[ITEM_MAILBOX].chr);
	encoder = dsync_ibc_send_encode_begin(ibc, ITEM_MAILBOX);
	dsync_serializer_encode_add(encoder, "mailbox_guid",
				    guid_128_to_string(dsync_box->mailbox_guid));

	if (dsync_box->mailbox_lost)
		dsync_serializer_encode_add(encoder, "mailbox_lost", "");
	if (dsync_box->mailbox_ignore)
		dsync_serializer_encode_add(encoder, "mailbox_ignore", "");
	if (dsync_box->have_guids)
		dsync_serializer_encode_add(encoder, "have_guids", "");
	if (dsync_box->have_save_guids)
		dsync_serializer_encode_add(encoder, "have_save_guids", "");
	if (dsync_box->have_only_guid128)
		dsync_serializer_encode_add(encoder, "have_only_guid128", "");
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
	dsync_serializer_encode_add(encoder, "highest_pvt_modseq",
				    dec2str(dsync_box->highest_pvt_modseq));

	value = get_cache_fields(ibc, dsync_box);
	if (value != NULL)
		dsync_serializer_encode_add(encoder, "cache_fields", value);

	dsync_serializer_encode_finish(&encoder, str);
	dsync_ibc_stream_send_string(ibc, str);
}

static int
parse_cache_field(struct dsync_ibc_stream *ibc, struct dsync_mailbox *box,
		  const char *value)
{
	struct dsync_deserializer_decoder *decoder;
	struct mailbox_cache_field field;
	const char *error;
	int ret = 0;

	if (dsync_deserializer_decode_begin(ibc->deserializers[ITEM_MAILBOX_CACHE_FIELD],
					    value, &decoder, &error) < 0) {
		dsync_ibc_input_error(ibc, NULL,
			"cache_field: Invalid input: %s", error);
		return -1;
	}

	i_zero(&field);
	value = dsync_deserializer_decode_get(decoder, "name");
	field.name = p_strdup(ibc->ret_pool, value);

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
		dsync_ibc_input_error(ibc, decoder, "Invalid decision: %s",
				      value);
		ret = -1;
		break;
	}
	if (value[1] == 'F')
		field.decision |= MAIL_CACHE_DECISION_FORCED;

	if (dsync_deserializer_decode_try(decoder, "last_used", &value) &&
	    str_to_time(value, &field.last_used) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid last_used");
		ret = -1;
	}
	array_push_back(&box->cache_fields, &field);

	dsync_deserializer_decode_finish(&decoder);
	return ret;
}

static enum dsync_ibc_recv_ret
dsync_ibc_stream_recv_mailbox(struct dsync_ibc *_ibc,
			      const struct dsync_mailbox **dsync_box_r)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	pool_t pool = ibc->ret_pool;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_mailbox *box;
	const char *value;
	enum dsync_ibc_recv_ret ret;

	p_clear(pool);
	box = p_new(pool, struct dsync_mailbox, 1);

	ret = dsync_ibc_stream_input_next(ibc, ITEM_MAILBOX, &decoder);
	if (ret != DSYNC_IBC_RECV_RET_OK)
		return ret;

	value = dsync_deserializer_decode_get(decoder, "mailbox_guid");
	if (guid_128_from_string(value, box->mailbox_guid) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid mailbox_guid");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}

	if (dsync_deserializer_decode_try(decoder, "mailbox_lost", &value))
		box->mailbox_lost = TRUE;
	if (dsync_deserializer_decode_try(decoder, "mailbox_ignore", &value))
		box->mailbox_ignore = TRUE;
	if (dsync_deserializer_decode_try(decoder, "have_guids", &value))
		box->have_guids = TRUE;
	if (dsync_deserializer_decode_try(decoder, "have_save_guids", &value) ||
	    (box->have_guids && ibc->minor_version < DSYNC_PROTOCOL_MINOR_HAVE_SAVE_GUID))
		box->have_save_guids = TRUE;
	if (dsync_deserializer_decode_try(decoder, "have_only_guid128", &value))
		box->have_only_guid128 = TRUE;
	value = dsync_deserializer_decode_get(decoder, "uid_validity");
	if (str_to_uint32(value, &box->uid_validity) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid uid_validity");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "uid_next");
	if (str_to_uint32(value, &box->uid_next) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid uid_next");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "messages_count");
	if (str_to_uint32(value, &box->messages_count) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid messages_count");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "first_recent_uid");
	if (str_to_uint32(value, &box->first_recent_uid) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid first_recent_uid");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "highest_modseq");
	if (str_to_uint64(value, &box->highest_modseq) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid highest_modseq");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	value = dsync_deserializer_decode_get(decoder, "highest_pvt_modseq");
	if (str_to_uint64(value, &box->highest_pvt_modseq) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid highest_pvt_modseq");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}

	p_array_init(&box->cache_fields, pool, 32);
	if (dsync_deserializer_decode_try(decoder, "cache_fields", &value)) {
		const char *const *fields = t_strsplit(value, "\n");
		for (; *fields != NULL; fields++) {
			if (parse_cache_field(ibc, box, *fields) < 0)
				return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
	}

	*dsync_box_r = box;
	return DSYNC_IBC_RECV_RET_OK;
}

static void
dsync_ibc_stream_send_mailbox_attribute(struct dsync_ibc *_ibc,
					const struct dsync_mailbox_attribute *attr)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);
	char type[2];

	if (ibc->minor_version < DSYNC_PROTOCOL_MINOR_HAVE_ATTRIBUTES)
		return;

	str_append_c(str, items[ITEM_MAILBOX_ATTRIBUTE].chr);
	encoder = dsync_ibc_send_encode_begin(ibc, ITEM_MAILBOX_ATTRIBUTE);

	type[0] = type[1] = '\0';
	switch (attr->type) {
	case MAIL_ATTRIBUTE_TYPE_PRIVATE:
		type[0] = 'p';
		break;
	case MAIL_ATTRIBUTE_TYPE_SHARED:
		type[0] = 's';
		break;
	}
	i_assert(type[0] != '\0');
	dsync_serializer_encode_add(encoder, "type", type);
	dsync_serializer_encode_add(encoder, "key", attr->key);
	if (attr->value != NULL)
		dsync_serializer_encode_add(encoder, "value", attr->value);
	else if (attr->value_stream != NULL)
		dsync_serializer_encode_add(encoder, "stream", "");

	if (attr->deleted)
		dsync_serializer_encode_add(encoder, "deleted", "");
	if (attr->last_change != 0) {
		dsync_serializer_encode_add(encoder, "last_change",
					    dec2str(attr->last_change));
	}
	if (attr->modseq != 0) {
		dsync_serializer_encode_add(encoder, "modseq",
					    dec2str(attr->modseq));
	}

	dsync_serializer_encode_finish(&encoder, str);
	dsync_ibc_stream_send_string(ibc, str);

	if (attr->value_stream != NULL) {
		ibc->value_output_last = '\0';
		ibc->value_output = attr->value_stream;
		i_stream_ref(ibc->value_output);
		(void)dsync_ibc_stream_send_value_stream(ibc);
	}
}

static enum dsync_ibc_recv_ret
dsync_ibc_stream_recv_mailbox_attribute(struct dsync_ibc *_ibc,
					const struct dsync_mailbox_attribute **attr_r)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	pool_t pool = ibc->ret_pool;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_mailbox_attribute *attr;
	const char *value;
	enum dsync_ibc_recv_ret ret;

	if (ibc->minor_version < DSYNC_PROTOCOL_MINOR_HAVE_ATTRIBUTES)
		return DSYNC_IBC_RECV_RET_FINISHED;

	if (ibc->value_input != NULL) {
		/* wait until the mail's stream has been read */
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}

	if (ibc->cur_attr != NULL) {
		/* finished reading the stream, return the mail now */
		*attr_r = ibc->cur_attr;
		ibc->cur_attr = NULL;
		return DSYNC_IBC_RECV_RET_OK;
	}

	p_clear(pool);
	attr = p_new(pool, struct dsync_mailbox_attribute, 1);

	ret = dsync_ibc_stream_input_next(ibc, ITEM_MAILBOX_ATTRIBUTE, &decoder);
	if (ret != DSYNC_IBC_RECV_RET_OK)
		return ret;

	value = dsync_deserializer_decode_get(decoder, "type");
	switch (*value) {
	case 'p':
		attr->type = MAIL_ATTRIBUTE_TYPE_PRIVATE;
		break;
	case 's':
		attr->type = MAIL_ATTRIBUTE_TYPE_SHARED;
		break;
	default:
		dsync_ibc_input_error(ibc, decoder, "Invalid type: %s", value);
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}

	value = dsync_deserializer_decode_get(decoder, "key");
	attr->key = p_strdup(pool, value);

	if (dsync_deserializer_decode_try(decoder, "deleted", &value))
		attr->deleted = TRUE;
	if (dsync_deserializer_decode_try(decoder, "last_change", &value) &&
	    str_to_time(value, &attr->last_change) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid last_change");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "modseq", &value) &&
	    str_to_uint64(value, &attr->modseq) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid modseq");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}

	/* NOTE: stream reading must be the last here, because reading a large
	   stream will be finished later by return TRYAGAIN. We need to
	   deserialize all the other fields before that or they'll get lost. */
	if (dsync_deserializer_decode_try(decoder, "stream", &value)) {
		attr->value_stream = dsync_ibc_stream_input_stream(ibc);
		if (dsync_ibc_stream_read_mail_stream(ibc) <= 0) {
			ibc->cur_attr = attr;
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
		/* already finished reading the stream */
		i_assert(ibc->value_input == NULL);
	} else if (dsync_deserializer_decode_try(decoder, "value", &value))
		attr->value = p_strdup(pool, value);

	*attr_r = attr;
	return DSYNC_IBC_RECV_RET_OK;
}

static void
dsync_ibc_stream_send_change(struct dsync_ibc *_ibc,
			     const struct dsync_mail_change *change)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);
	char type[2];

	str_append_c(str, items[ITEM_MAIL_CHANGE].chr);
	encoder = dsync_ibc_send_encode_begin(ibc, ITEM_MAIL_CHANGE);

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
	if (change->pvt_modseq != 0) {
		dsync_serializer_encode_add(encoder, "pvt_modseq",
					    dec2str(change->pvt_modseq));
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
		str_append_tabescaped(kw_str, changes[0]);
		for (i = 1; i < count; i++) {
			str_append_c(kw_str, '\t');
			str_append_tabescaped(kw_str, changes[i]);
		}
		dsync_serializer_encode_add(encoder, "keyword_changes",
					    str_c(kw_str));
	}
	if (change->received_timestamp > 0) {
		dsync_serializer_encode_add(encoder, "received_timestamp",
			t_strdup_printf("%"PRIxTIME_T, change->received_timestamp));
	}
	if (change->virtual_size > 0) {
		dsync_serializer_encode_add(encoder, "virtual_size",
			t_strdup_printf("%llx", (unsigned long long)change->virtual_size));
	}

	dsync_serializer_encode_finish(&encoder, str);
	dsync_ibc_stream_send_string(ibc, str);
}

static enum dsync_ibc_recv_ret
dsync_ibc_stream_recv_change(struct dsync_ibc *_ibc,
			     const struct dsync_mail_change **change_r)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	pool_t pool = ibc->ret_pool;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_mail_change *change;
	const char *value;
	unsigned int uintval;
	unsigned long long ullongval;
	enum dsync_ibc_recv_ret ret;

	p_clear(pool);
	change = p_new(pool, struct dsync_mail_change, 1);

	ret = dsync_ibc_stream_input_next(ibc, ITEM_MAIL_CHANGE, &decoder);
	if (ret != DSYNC_IBC_RECV_RET_OK)
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
		dsync_ibc_input_error(ibc, decoder, "Invalid type: %s", value);
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}

	value = dsync_deserializer_decode_get(decoder, "uid");
	if (str_to_uint32(value, &change->uid) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid uid");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}

	if (dsync_deserializer_decode_try(decoder, "guid", &value))
		change->guid = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "hdr_hash", &value))
		change->hdr_hash = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "modseq", &value) &&
	    str_to_uint64(value, &change->modseq) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid modseq");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "pvt_modseq", &value) &&
	    str_to_uint64(value, &change->pvt_modseq) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid pvt_modseq");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}

	if (dsync_deserializer_decode_try(decoder, "add_flags", &value)) {
		if (str_to_uint_hex(value, &uintval) < 0 ||
		    uintval > (uint8_t)-1) {
			dsync_ibc_input_error(ibc, decoder,
				"Invalid add_flags: %s", value);
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
		change->add_flags = uintval;
	}
	if (dsync_deserializer_decode_try(decoder, "remove_flags", &value)) {
		if (str_to_uint_hex(value, &uintval) < 0 ||
		    uintval > (uint8_t)-1) {
			dsync_ibc_input_error(ibc, decoder,
				"Invalid remove_flags: %s", value);
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
		change->remove_flags = uintval;
	}
	if (dsync_deserializer_decode_try(decoder, "final_flags", &value)) {
		if (str_to_uint_hex(value, &uintval) < 0 ||
		    uintval > (uint8_t)-1) {
			dsync_ibc_input_error(ibc, decoder,
				"Invalid final_flags: %s", value);
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
		change->final_flags = uintval;
	}
	if (dsync_deserializer_decode_try(decoder, "keywords_reset", &value))
		change->keywords_reset = TRUE;

	if (dsync_deserializer_decode_try(decoder, "keyword_changes", &value) &&
	    *value != '\0') {
		const char *const *changes = t_strsplit_tabescaped(value);
		unsigned int i, count = str_array_length(changes);

		p_array_init(&change->keyword_changes, pool, count);
		for (i = 0; i < count; i++) {
			value = p_strdup(pool, changes[i]);
			array_push_back(&change->keyword_changes, &value);
		}
	}
	if (dsync_deserializer_decode_try(decoder, "received_timestamp", &value)) {
		if (str_to_ullong_hex(value, &ullongval) < 0) {
			dsync_ibc_input_error(ibc, decoder, "Invalid received_timestamp");
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
		change->received_timestamp = ullongval;
	}
	if (dsync_deserializer_decode_try(decoder, "virtual_size", &value)) {
		if (str_to_ullong_hex(value, &ullongval) < 0) {
			dsync_ibc_input_error(ibc, decoder, "Invalid virtual_size");
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
		change->virtual_size = ullongval;
	}

	*change_r = change;
	return DSYNC_IBC_RECV_RET_OK;
}

static void
dsync_ibc_stream_send_mail_request(struct dsync_ibc *_ibc,
				   const struct dsync_mail_request *request)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);

	str_append_c(str, items[ITEM_MAIL_REQUEST].chr);
	encoder = dsync_ibc_send_encode_begin(ibc, ITEM_MAIL_REQUEST);
	if (request->guid != NULL)
		dsync_serializer_encode_add(encoder, "guid", request->guid);
	if (request->uid != 0) {
		dsync_serializer_encode_add(encoder, "uid",
					    dec2str(request->uid));
	}
	dsync_serializer_encode_finish(&encoder, str);
	dsync_ibc_stream_send_string(ibc, str);
}

static enum dsync_ibc_recv_ret
dsync_ibc_stream_recv_mail_request(struct dsync_ibc *_ibc,
				   const struct dsync_mail_request **request_r)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_mail_request *request;
	const char *value;
	enum dsync_ibc_recv_ret ret;

	p_clear(ibc->ret_pool);
	request = p_new(ibc->ret_pool, struct dsync_mail_request, 1);

	ret = dsync_ibc_stream_input_next(ibc, ITEM_MAIL_REQUEST, &decoder);
	if (ret != DSYNC_IBC_RECV_RET_OK)
		return ret;

	if (dsync_deserializer_decode_try(decoder, "guid", &value))
		request->guid = p_strdup(ibc->ret_pool, value);
	if (dsync_deserializer_decode_try(decoder, "uid", &value) &&
	    str_to_uint32(value, &request->uid) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid uid");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}

	*request_r = request;
	return DSYNC_IBC_RECV_RET_OK;
}

static void
dsync_ibc_stream_send_mail(struct dsync_ibc *_ibc,
			   const struct dsync_mail *mail)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);

	i_assert(!mail->minimal_fields);
	i_assert(ibc->value_output == NULL);

	str_append_c(str, items[ITEM_MAIL].chr);
	encoder = dsync_ibc_send_encode_begin(ibc, ITEM_MAIL);
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
	if (mail->saved_date != 0) {
		dsync_serializer_encode_add(encoder, "saved_date",
					    dec2str(mail->saved_date));
	}
	if (mail->input != NULL)
		dsync_serializer_encode_add(encoder, "stream", "");

	dsync_serializer_encode_finish(&encoder, str);
	dsync_ibc_stream_send_string(ibc, str);

	if (mail->input != NULL) {
		ibc->value_output_last = '\0';
		ibc->value_output = mail->input;
		i_stream_ref(ibc->value_output);
		(void)dsync_ibc_stream_send_value_stream(ibc);
	}
}

static enum dsync_ibc_recv_ret
dsync_ibc_stream_recv_mail(struct dsync_ibc *_ibc, struct dsync_mail **mail_r)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	pool_t pool = ibc->ret_pool;
	struct dsync_deserializer_decoder *decoder;
	struct dsync_mail *mail;
	const char *value;
	enum dsync_ibc_recv_ret ret;

	if (ibc->value_input != NULL) {
		/* wait until the mail's stream has been read */
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (ibc->cur_mail != NULL) {
		/* finished reading the stream, return the mail now */
		*mail_r = ibc->cur_mail;
		ibc->cur_mail = NULL;
		return DSYNC_IBC_RECV_RET_OK;
	}

	p_clear(pool);
	mail = p_new(pool, struct dsync_mail, 1);

	ret = dsync_ibc_stream_input_next(ibc, ITEM_MAIL, &decoder);
	if (ret != DSYNC_IBC_RECV_RET_OK)
		return ret;

	if (dsync_deserializer_decode_try(decoder, "guid", &value))
		mail->guid = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "uid", &value) &&
	    str_to_uint32(value, &mail->uid) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid uid");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "pop3_uidl", &value))
		mail->pop3_uidl = p_strdup(pool, value);
	if (dsync_deserializer_decode_try(decoder, "pop3_order", &value) &&
	    str_to_uint32(value, &mail->pop3_order) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid pop3_order");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "received_date", &value) &&
	    str_to_time(value, &mail->received_date) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid received_date");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "saved_date", &value) &&
	    str_to_time(value, &mail->saved_date) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid saved_date");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "stream", &value)) {
		mail->input = dsync_ibc_stream_input_stream(ibc);
		if (dsync_ibc_stream_read_mail_stream(ibc) <= 0) {
			ibc->cur_mail = mail;
			return DSYNC_IBC_RECV_RET_TRYAGAIN;
		}
		/* already finished reading the stream */
		i_assert(ibc->value_input == NULL);
	}

	*mail_r = mail;
	return DSYNC_IBC_RECV_RET_OK;
}

static void
dsync_ibc_stream_send_finish(struct dsync_ibc *_ibc, const char *error,
			     enum mail_error mail_error,
			     bool require_full_resync)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_serializer_encoder *encoder;
	string_t *str = t_str_new(128);

	str_append_c(str, items[ITEM_FINISH].chr);
	encoder = dsync_ibc_send_encode_begin(ibc, ITEM_FINISH);
	if (error != NULL)
		dsync_serializer_encode_add(encoder, "error", error);
	if (mail_error != 0) {
		dsync_serializer_encode_add(encoder, "mail_error",
					    dec2str(mail_error));
	}
	if (require_full_resync)
		dsync_serializer_encode_add(encoder, "require_full_resync", "");
	dsync_serializer_encode_finish(&encoder, str);
	dsync_ibc_stream_send_string(ibc, str);
}

static enum dsync_ibc_recv_ret
dsync_ibc_stream_recv_finish(struct dsync_ibc *_ibc, const char **error_r,
			     enum mail_error *mail_error_r,
			     bool *require_full_resync_r)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	struct dsync_deserializer_decoder *decoder;
	const char *value;
	enum dsync_ibc_recv_ret ret;
	int i = 0;

	*error_r = NULL;
	*mail_error_r = 0;
	*require_full_resync_r = FALSE;

	p_clear(ibc->ret_pool);

	if (ibc->minor_version < DSYNC_PROTOCOL_MINOR_HAVE_FINISH)
		return DSYNC_IBC_RECV_RET_OK;

	ret = dsync_ibc_stream_input_next(ibc, ITEM_FINISH, &decoder);
	if (ret != DSYNC_IBC_RECV_RET_OK)
		return ret;

	if (dsync_deserializer_decode_try(decoder, "error", &value))
		*error_r = p_strdup(ibc->ret_pool, value);
	if (dsync_deserializer_decode_try(decoder, "mail_error", &value) &&
	    str_to_int(value, &i) < 0) {
		dsync_ibc_input_error(ibc, decoder, "Invalid mail_error");
		return DSYNC_IBC_RECV_RET_TRYAGAIN;
	}
	if (dsync_deserializer_decode_try(decoder, "require_full_resync", &value))
		*require_full_resync_r = TRUE;
	*mail_error_r = i;

	ibc->finish_received = TRUE;
	return DSYNC_IBC_RECV_RET_OK;
}

static void dsync_ibc_stream_close_mail_streams(struct dsync_ibc *_ibc)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;

	if (ibc->value_output != NULL) {
		i_stream_unref(&ibc->value_output);
		dsync_ibc_stream_stop(ibc);
	}
}

static bool dsync_ibc_stream_is_send_queue_full(struct dsync_ibc *_ibc)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;
	size_t bytes;

	if (ibc->value_output != NULL)
		return TRUE;

	bytes = o_stream_get_buffer_used_size(ibc->output);
	if (bytes < DSYNC_IBC_STREAM_OUTBUF_THROTTLE_SIZE)
		return FALSE;

	o_stream_set_flush_pending(ibc->output, TRUE);
	return TRUE;
}

static bool dsync_ibc_stream_has_pending_data(struct dsync_ibc *_ibc)
{
	struct dsync_ibc_stream *ibc = (struct dsync_ibc_stream *)_ibc;

	return ibc->has_pending_data;
}

static const struct dsync_ibc_vfuncs dsync_ibc_stream_vfuncs = {
	dsync_ibc_stream_deinit,
	dsync_ibc_stream_send_handshake,
	dsync_ibc_stream_recv_handshake,
	dsync_ibc_stream_send_end_of_list,
	dsync_ibc_stream_send_mailbox_state,
	dsync_ibc_stream_recv_mailbox_state,
	dsync_ibc_stream_send_mailbox_tree_node,
	dsync_ibc_stream_recv_mailbox_tree_node,
	dsync_ibc_stream_send_mailbox_deletes,
	dsync_ibc_stream_recv_mailbox_deletes,
	dsync_ibc_stream_send_mailbox,
	dsync_ibc_stream_recv_mailbox,
	dsync_ibc_stream_send_mailbox_attribute,
	dsync_ibc_stream_recv_mailbox_attribute,
	dsync_ibc_stream_send_change,
	dsync_ibc_stream_recv_change,
	dsync_ibc_stream_send_mail_request,
	dsync_ibc_stream_recv_mail_request,
	dsync_ibc_stream_send_mail,
	dsync_ibc_stream_recv_mail,
	dsync_ibc_stream_send_finish,
	dsync_ibc_stream_recv_finish,
	dsync_ibc_stream_close_mail_streams,
	dsync_ibc_stream_is_send_queue_full,
	dsync_ibc_stream_has_pending_data
};

struct dsync_ibc *
dsync_ibc_init_stream(struct istream *input, struct ostream *output,
		      const char *name, const char *temp_path_prefix,
		      unsigned int timeout_secs)
{
	struct dsync_ibc_stream *ibc;

	ibc = i_new(struct dsync_ibc_stream, 1);
	ibc->ibc.v = dsync_ibc_stream_vfuncs;
	ibc->input = input;
	ibc->output = output;
	i_stream_ref(ibc->input);
	o_stream_ref(ibc->output);
	ibc->name = i_strdup(name);
	ibc->temp_path_prefix = i_strdup(temp_path_prefix);
	ibc->timeout_secs = timeout_secs;
	ibc->ret_pool = pool_alloconly_create("ibc stream data", 2048);
	dsync_ibc_stream_init(ibc);
	return &ibc->ibc;
}
