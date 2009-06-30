/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fd-set-nonblock.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "imap-util.h"
#include "dsync-proxy.h"
#include "dsync-worker-private.h"

#include <stdlib.h>
#include <unistd.h>

#define OUTBUF_THROTTLE_SIZE (1024*64)

struct proxy_client_dsync_worker_mailbox_iter {
	struct dsync_worker_mailbox_iter iter;
	pool_t pool;
};

struct proxy_client_dsync_worker {
	struct dsync_worker worker;
	int fd_in, fd_out;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	mailbox_guid_t selected_box_guid;
	struct istream *save_input;
	unsigned int save_input_last_lf:1;
};

extern struct dsync_worker_vfuncs proxy_client_dsync_worker;

static void proxy_client_send_stream(struct proxy_client_dsync_worker *worker);

static void proxy_client_worker_input(struct proxy_client_dsync_worker *worker)
{
	i_assert(worker->worker.input_callback != NULL);
	worker->worker.input_callback(worker->worker.input_context);
}

static int proxy_client_worker_output(struct proxy_client_dsync_worker *worker)
{
	int ret;

	if ((ret = o_stream_flush(worker->output)) < 0)
		return 1;

	if (worker->save_input != NULL) {
		/* proxy_client_worker_msg_save() hasn't finished yet. */
		o_stream_cork(worker->output);
		proxy_client_send_stream(worker);
		if (worker->save_input != NULL)
			return 1;
	}

	if (worker->worker.output_callback != NULL)
		worker->worker.output_callback(worker->worker.output_context);
	return ret;
}

struct dsync_worker *dsync_worker_init_proxy_client(int fd_in, int fd_out)
{
	struct proxy_client_dsync_worker *worker;

	worker = i_new(struct proxy_client_dsync_worker, 1);
	worker->worker.v = proxy_client_dsync_worker;
	worker->fd_in = fd_in;
	worker->fd_out = fd_out;
	worker->io = io_add(fd_in, IO_READ, proxy_client_worker_input, worker);
	worker->input = i_stream_create_fd(fd_in, (size_t)-1, FALSE);
	worker->output = o_stream_create_fd(fd_out, (size_t)-1, FALSE);
	/* we'll keep the output corked until flush is needed */
	o_stream_cork(worker->output);
	o_stream_set_flush_callback(worker->output, proxy_client_worker_output,
				    worker);
	fd_set_nonblock(fd_in, TRUE);
	fd_set_nonblock(fd_out, TRUE);
	return &worker->worker;
}

static void proxy_client_worker_deinit(struct dsync_worker *_worker)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	io_remove(&worker->io);
	i_stream_destroy(&worker->input);
	o_stream_destroy(&worker->output);
	if (close(worker->fd_in) < 0)
		i_error("close(worker input) failed: %m");
	if (worker->fd_in != worker->fd_out) {
		if (close(worker->fd_out) < 0)
			i_error("close(worker output) failed: %m");
	}
	i_free(worker);
}

static int
proxy_client_worker_read_line(struct proxy_client_dsync_worker *worker,
			      const char **line_r)
{
	*line_r = i_stream_read_next_line(worker->input);
	if (*line_r == NULL) {
		if (worker->input->stream_errno != 0) {
			errno = worker->input->stream_errno;
			i_error("read() from worker server failed: %m");
			return -1;
		}
		if (worker->input->eof) {
			i_error("worker server disconnected unexpectedly");
			return -1;
		}
	}
	return *line_r != NULL ? 1 : 0;
}

static uint32_t
proxy_client_worker_next_tag(struct proxy_client_dsync_worker *worker)
{
	uint32_t ret;

	ret = worker->worker.next_tag;
	worker->worker.next_tag = 0;
	return ret;
}

static bool proxy_client_worker_get_next_result(struct dsync_worker *_worker,
						uint32_t *tag_r, int *result_r)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;
	const char *line;
	bool ret = TRUE;

	if (proxy_client_worker_read_line(worker, &line) <= 0)
		return FALSE;

	T_BEGIN {
		const char *const *args;

		args = t_strsplit(line, "\t");
		*tag_r = strtoul(args[0], NULL, 10);
		*result_r = strtol(args[1], NULL, 10);

		if (args[0] == NULL || args[1] == NULL || *tag_r == 0) {
			i_error("Invalid input from worker server: %s", line);
			ret = FALSE;
		}
	} T_END;
	return ret;
}

static bool proxy_client_worker_is_output_full(struct dsync_worker *_worker)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	return o_stream_get_buffer_used_size(worker->output) >=
		OUTBUF_THROTTLE_SIZE;
}

static int proxy_client_worker_output_flush(struct dsync_worker *_worker)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	if (o_stream_flush(worker->output) < 0)
		return -1;

	o_stream_uncork(worker->output);
	if (o_stream_get_buffer_used_size(worker->output) > 0)
		return 0;
	o_stream_cork(worker->output);
	return 1;
}

static struct dsync_worker_mailbox_iter *
proxy_client_worker_mailbox_iter_init(struct dsync_worker *_worker)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;
	struct proxy_client_dsync_worker_mailbox_iter *iter;

	iter = i_new(struct proxy_client_dsync_worker_mailbox_iter, 1);
	iter->iter.worker = _worker;
	iter->pool = pool_alloconly_create("proxy mailbox iter", 1024);
	o_stream_send_str(worker->output,
		t_strdup_printf("%u\tBOX-LIST\n",
				proxy_client_worker_next_tag(worker)));
	proxy_client_worker_output_flush(_worker);
	return &iter->iter;
}

static int
proxy_client_worker_mailbox_iter_next(struct dsync_worker_mailbox_iter *_iter,
				      struct dsync_mailbox *dsync_box_r)
{
	struct proxy_client_dsync_worker_mailbox_iter *iter =
		(struct proxy_client_dsync_worker_mailbox_iter *)_iter;
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_iter->worker;
	const char *line, *error;
	int ret;

	if ((ret = proxy_client_worker_read_line(worker, &line)) <= 0) {
		if (ret < 0)
			_iter->failed = TRUE;
		return ret;
	}

	if (*line == '\t') {
		/* end of mailboxes */
		if (line[1] != '0')
			_iter->failed = TRUE;
		return -1;
	}

	p_clear(iter->pool);
	if (dsync_proxy_mailbox_import(iter->pool, line,
				       dsync_box_r, &error) < 0) {
		i_error("Invalid mailbox input from worker server: %s", error);
		_iter->failed = TRUE;
		return -1;
	}
	return 1;
}

static int
proxy_client_worker_mailbox_iter_deinit(struct dsync_worker_mailbox_iter *_iter)
{
	struct proxy_client_dsync_worker_mailbox_iter *iter =
		(struct proxy_client_dsync_worker_mailbox_iter *)_iter;
	int ret = _iter->failed ? -1 : 0;

	pool_unref(&iter->pool);
	i_free(iter);
	return ret;
}

struct proxy_client_dsync_worker_msg_iter {
	struct dsync_worker_msg_iter iter;
	pool_t pool;
	bool done;
};

static struct dsync_worker_msg_iter *
proxy_client_worker_msg_iter_init(struct dsync_worker *_worker,
				  const mailbox_guid_t mailboxes[],
				  unsigned int mailbox_count)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;
	struct proxy_client_dsync_worker_msg_iter *iter;
	string_t *str;
	unsigned int i;

	iter = i_new(struct proxy_client_dsync_worker_msg_iter, 1);
	iter->iter.worker = _worker;
	iter->pool = pool_alloconly_create("proxy message iter", 1024);

	str = t_str_new(512);
	str_printfa(str, "%u\tMSG-LIST",
		    proxy_client_worker_next_tag(worker));
	for (i = 0; i < mailbox_count; i++) {
		str_append_c(str, '\t');
		dsync_proxy_mailbox_guid_export(str, &mailboxes[i]);
	}
	str_append_c(str, '\n');
	o_stream_send(worker->output, str_data(str), str_len(str));
	proxy_client_worker_output_flush(_worker);
	return &iter->iter;
}

static int
proxy_client_worker_msg_iter_next(struct dsync_worker_msg_iter *_iter,
				  unsigned int *mailbox_idx_r,
				  struct dsync_message *msg_r)
{
	struct proxy_client_dsync_worker_msg_iter *iter =
		(struct proxy_client_dsync_worker_msg_iter *)_iter;
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_iter->worker;
	const char *line, *error;
	int ret;

	if (iter->done)
		return -1;

	if ((ret = proxy_client_worker_read_line(worker, &line)) <= 0) {
		if (ret < 0)
			_iter->failed = TRUE;
		return ret;
	}

	if (*line == '\t') {
		/* end of messages */
		if (line[1] != '0')
			_iter->failed = TRUE;
		iter->done = TRUE;
		return -1;
	}

	*mailbox_idx_r = 0;
	while (*line >= '0' && *line <= '9') {
		*mailbox_idx_r = *mailbox_idx_r * 10 + (*line - '0');
		line++;
	}
	if (*line != '\t') {
		i_error("Invalid mailbox idx from worker server");
		_iter->failed = TRUE;
		return -1;
	}
	line++;

	p_clear(iter->pool);
	if (dsync_proxy_msg_import(iter->pool, line, msg_r, &error) < 0) {
		i_error("Invalid message input from worker server: %s", error);
		_iter->failed = TRUE;
		return -1;
	}
	return 1;
}

static int
proxy_client_worker_msg_iter_deinit(struct dsync_worker_msg_iter *_iter)
{
	struct proxy_client_dsync_worker_msg_iter *iter =
		(struct proxy_client_dsync_worker_msg_iter *)_iter;
	int ret = _iter->failed ? -1 : 0;

	pool_unref(&iter->pool);
	i_free(iter);
	return ret;
}

static void
proxy_client_worker_create_mailbox(struct dsync_worker *_worker,
				   const struct dsync_mailbox *dsync_box)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_printfa(str, "%u\tBOX-CREATE\t",
			    proxy_client_worker_next_tag(worker));
		str_tabescape_write(str, dsync_box->name);
		if (dsync_box->uid_validity != 0) {
			str_append_c(str, '\t');
			dsync_proxy_mailbox_guid_export(str, &dsync_box->guid);
			str_printfa(str, "\t%u\n", dsync_box->uid_validity);
		}
		o_stream_send(worker->output, str_data(str), str_len(str));
	} T_END;
}

static void
proxy_client_worker_update_mailbox(struct dsync_worker *_worker,
				   const struct dsync_mailbox *dsync_box)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_printfa(str, "%u\tBOX-UPDATE\t",
			    proxy_client_worker_next_tag(worker));
		str_tabescape_write(str, dsync_box->name);
		str_append_c(str, '\t');
		dsync_proxy_mailbox_guid_export(str, &dsync_box->guid);
		str_printfa(str, "\t%u\t%u\t%llu\n",
			    dsync_box->uid_validity, dsync_box->uid_next,
			    (unsigned long long)dsync_box->highest_modseq);
		o_stream_send(worker->output, str_data(str), str_len(str));
	} T_END;
}

static void
proxy_client_worker_select_mailbox(struct dsync_worker *_worker,
				   const mailbox_guid_t *mailbox)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	i_assert(worker->worker.next_tag == 0);

	if (memcmp(worker->selected_box_guid.guid, mailbox->guid,
		   sizeof(worker->selected_box_guid.guid)) == 0)
		return;
	worker->selected_box_guid = *mailbox;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_printfa(str, "%u\tBOX-SELECT\t",
			    proxy_client_worker_next_tag(worker));
		dsync_proxy_mailbox_guid_export(str, mailbox);
		str_append_c(str, '\n');
		o_stream_send(worker->output, str_data(str), str_len(str));
	} T_END;
}

static void
proxy_client_worker_msg_update_metadata(struct dsync_worker *_worker,
					const struct dsync_message *msg)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_printfa(str, "%u\tMSG-UPDATE\t%u\t%llu\t",
			    proxy_client_worker_next_tag(worker), msg->uid,
			    (unsigned long long)msg->modseq);
		imap_write_flags(str, msg->flags & ~MAIL_RECENT, msg->keywords);
		str_append_c(str, '\n');
		o_stream_send(worker->output, str_data(str), str_len(str));
	} T_END;
}

static void
proxy_client_worker_msg_update_uid(struct dsync_worker *_worker, uint32_t uid)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		o_stream_send_str(worker->output,
			t_strdup_printf("%u\tMSG-UID-CHANGE\t%u\n",
				proxy_client_worker_next_tag(worker), uid));
	} T_END;
}

static void
proxy_client_worker_msg_expunge(struct dsync_worker *_worker, uint32_t uid)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		o_stream_send_str(worker->output,
			t_strdup_printf("%u\tMSG-EXPUNGE\t%u\n",
				proxy_client_worker_next_tag(worker), uid));
	} T_END;
}

static void
proxy_client_worker_msg_copy(struct dsync_worker *_worker,
			     const mailbox_guid_t *src_mailbox,
			     uint32_t src_uid,
			     const struct dsync_message *dest_msg)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_printfa(str, "%u\tMSG-COPY\t",
			    proxy_client_worker_next_tag(worker));
		dsync_proxy_mailbox_guid_export(str, src_mailbox);
		str_printfa(str, "\t%u\t", src_uid);
		dsync_proxy_msg_export(str, dest_msg);
		str_append_c(str, '\n');
		o_stream_send(worker->output, str_data(str), str_len(str));
	} T_END;
}

static void proxy_client_send_stream(struct proxy_client_dsync_worker *worker)
{
	const unsigned char *data;
	size_t i, start, size;

	while (i_stream_read_data(worker->save_input, &data, &size, 0) > 0) {
		if (worker->save_input_last_lf && data[0] == '.')
			o_stream_send(worker->output, ".", 1);

		for (i = 1, start = 0; i < size; i++) {
			if (data[i-1] == '\n' && data[i] == '.') {
				o_stream_send(worker->output, data + start,
					      i - start);
				o_stream_send(worker->output, ".", 1);
				start = i;
			}
		}
		o_stream_send(worker->output, data + start, i - start);
		i_stream_skip(worker->save_input, i);

		worker->save_input_last_lf = data[i-1] == '\n';

		if (proxy_client_worker_is_output_full(&worker->worker)) {
			o_stream_uncork(worker->output);
			if (proxy_client_worker_is_output_full(&worker->worker))
				return;
			o_stream_cork(worker->output);
		}
	}
	i_assert(size == 0);
	o_stream_send(worker->output, "\n.\n", 3);
	worker->save_input = NULL;
}

static void
proxy_client_worker_msg_save(struct dsync_worker *_worker,
			     const struct dsync_message *msg,
			     struct dsync_msg_static_data *data)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_printfa(str, "%u\tMSG-SAVE\t%ld\t",
			    proxy_client_worker_next_tag(worker),
			    (long)data->received_date);
		str_tabescape_write(str, data->pop3_uidl);
		str_append_c(str, '\t');
		dsync_proxy_msg_export(str, msg);
		str_append_c(str, '\n');
		o_stream_send(worker->output, str_data(str), str_len(str));
	} T_END;

	i_assert(worker->save_input == NULL);
	worker->save_input = data->input;
	worker->save_input_last_lf = TRUE;
	proxy_client_send_stream(worker);
}

static int
proxy_client_worker_msg_get(struct dsync_worker *worker ATTR_UNUSED,
			    uint32_t uid ATTR_UNUSED,
			    struct dsync_msg_static_data *data_r ATTR_UNUSED)
{
	i_panic("proxy not supported for getting messages");
	return -1;
}

struct dsync_worker_vfuncs proxy_client_dsync_worker = {
	proxy_client_worker_deinit,

	proxy_client_worker_get_next_result,
	proxy_client_worker_is_output_full,
	proxy_client_worker_output_flush,

	proxy_client_worker_mailbox_iter_init,
	proxy_client_worker_mailbox_iter_next,
	proxy_client_worker_mailbox_iter_deinit,

	proxy_client_worker_msg_iter_init,
	proxy_client_worker_msg_iter_next,
	proxy_client_worker_msg_iter_deinit,

	proxy_client_worker_create_mailbox,
	proxy_client_worker_update_mailbox,

	proxy_client_worker_select_mailbox,
	proxy_client_worker_msg_update_metadata,
	proxy_client_worker_msg_update_uid,
	proxy_client_worker_msg_expunge,
	proxy_client_worker_msg_copy,
	proxy_client_worker_msg_save,
	proxy_client_worker_msg_get
};
