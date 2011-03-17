/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "aqueue.h"
#include "fd-set-nonblock.h"
#include "istream.h"
#include "istream-dot.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "master-service.h"
#include "imap-util.h"
#include "dsync-proxy.h"
#include "dsync-worker-private.h"

#include <stdlib.h>
#include <unistd.h>

#define OUTBUF_THROTTLE_SIZE (1024*64)

enum proxy_client_request_type {
	PROXY_CLIENT_REQUEST_TYPE_COPY,
	PROXY_CLIENT_REQUEST_TYPE_GET,
	PROXY_CLIENT_REQUEST_TYPE_FINISH
};

struct proxy_client_request {
	enum proxy_client_request_type type;
	uint32_t uid;
	union {
		dsync_worker_msg_callback_t *get;
		dsync_worker_copy_callback_t *copy;
		dsync_worker_finish_callback_t *finish;
	} callback;
	void *context;
};

struct proxy_client_dsync_worker_mailbox_iter {
	struct dsync_worker_mailbox_iter iter;
	pool_t pool;
};

struct proxy_client_dsync_worker_subs_iter {
	struct dsync_worker_subs_iter iter;
	pool_t pool;
};

struct proxy_client_dsync_worker {
	struct dsync_worker worker;
	int fd_in, fd_out;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to, *to_input;

	mailbox_guid_t selected_box_guid;

	dsync_worker_save_callback_t *save_callback;
	void *save_context;
	struct istream *save_input;
	struct io *save_io;
	bool save_input_last_lf;

	pool_t msg_get_pool;
	struct dsync_msg_static_data msg_get_data;
	ARRAY_DEFINE(request_array, struct proxy_client_request);
	struct aqueue *request_queue;
	string_t *pending_commands;

	unsigned int handshake_received:1;
	unsigned int finishing:1;
	unsigned int finished:1;
};

extern struct dsync_worker_vfuncs proxy_client_dsync_worker;

static void proxy_client_worker_input(struct proxy_client_dsync_worker *worker);
static void proxy_client_send_stream(struct proxy_client_dsync_worker *worker);

static void proxy_client_fail(struct proxy_client_dsync_worker *worker)
{
	i_stream_close(worker->input);
	dsync_worker_set_failure(&worker->worker);
	master_service_stop(master_service);
}

static int
proxy_client_worker_read_line(struct proxy_client_dsync_worker *worker,
			      const char **line_r)
{
	if (worker->worker.failed)
		return -1;

	*line_r = i_stream_read_next_line(worker->input);
	if (*line_r == NULL) {
		if (worker->input->stream_errno != 0) {
			errno = worker->input->stream_errno;
			i_error("read() from worker server failed: %m");
			dsync_worker_set_failure(&worker->worker);
			return -1;
		}
		if (worker->input->eof) {
			if (!worker->finished)
				i_error("read() from worker server failed: EOF");
			dsync_worker_set_failure(&worker->worker);
			return -1;
		}
	}
	if (*line_r == NULL)
		return 0;

	if (!worker->handshake_received) {
		if (strcmp(*line_r, DSYNC_PROXY_SERVER_GREETING_LINE) != 0) {
			i_error("Invalid server handshake: %s", *line_r);
			dsync_worker_set_failure(&worker->worker);
			return -1;
		}
		worker->handshake_received = TRUE;
		return proxy_client_worker_read_line(worker, line_r);
	}
	return 1;
}

static void
proxy_client_worker_msg_get_finish(struct proxy_client_dsync_worker *worker)
{
	worker->msg_get_data.input = NULL;
	worker->io = io_add(worker->fd_in, IO_READ,
			    proxy_client_worker_input, worker);

	/* some input may already be buffered. note that we may be coming here
	   from the input function itself, in which case this timeout must not
	   be called (we'll remove it later) */
	if (worker->to_input == NULL) {
		worker->to_input =
			timeout_add(0, proxy_client_worker_input, worker);
	}
}

static void
proxy_client_worker_read_to_eof(struct proxy_client_dsync_worker *worker)
{
	struct istream *input = worker->msg_get_data.input;
	const unsigned char *data;
	size_t size;
	int ret;

	while ((ret = i_stream_read_data(input, &data, &size, 0)) > 0)
		i_stream_skip(input, size);
	if (ret == -1) {
		i_stream_unref(&input);
		io_remove(&worker->io);
		proxy_client_worker_msg_get_finish(worker);
	}
	timeout_reset(worker->to);
}

static void
proxy_client_worker_msg_get_done(struct proxy_client_dsync_worker *worker)
{
	struct istream *input = worker->msg_get_data.input;

	i_assert(worker->io == NULL);

	if (input->eof)
		proxy_client_worker_msg_get_finish(worker);
	else {
		/* saving read the message only partially. we'll need to read
		   the input until EOF or we'll start treating the input as
		   commands. */
		worker->io = io_add(worker->fd_in, IO_READ,
				    proxy_client_worker_read_to_eof, worker);
		worker->msg_get_data.input =
			i_stream_create_dot(worker->input, FALSE);
	}
}

static bool
proxy_client_worker_next_copy(struct proxy_client_dsync_worker *worker,
			      const struct proxy_client_request *request,
			      const char *line)
{
	uint32_t uid;
	bool success;

	if (line[0] == '1' && line[1] == '\t')
		success = TRUE;
	else if (line[0] == '0' && line[1] == '\t')
		success = FALSE;
	else {
		i_error("msg-copy returned invalid input: %s", line);
		proxy_client_fail(worker);
		return FALSE;
	}
	uid = strtoul(line + 2, NULL, 10);
	if (uid != request->uid) {
		i_error("msg-copy returned invalid uid: %u != %u",
			uid, request->uid);
		proxy_client_fail(worker);
		return FALSE;
	}

	request->callback.copy(success, request->context);
	return TRUE;
}

static bool
proxy_client_worker_next_msg_get(struct proxy_client_dsync_worker *worker,
				 const struct proxy_client_request *request,
				 const char *line)
{
	enum dsync_msg_get_result result = DSYNC_MSG_GET_RESULT_FAILED;
	const char *p, *error;
	uint32_t uid;

	p_clear(worker->msg_get_pool);
	switch (line[0]) {
	case '1':
		/* ok */
		if (line[1] != '\t')
			break;
		line += 2;

		if ((p = strchr(line, '\t')) == NULL)
			break;
		uid = strtoul(t_strcut(line, '\t'), NULL, 10);
		line = p + 1;

		if (uid != request->uid) {
			i_error("msg-get returned invalid uid: %u != %u",
				uid, request->uid);
			proxy_client_fail(worker);
			return FALSE;
		}

		if (dsync_proxy_msg_static_import(worker->msg_get_pool,
						  line, &worker->msg_get_data,
						  &error) < 0) {
			i_error("Invalid msg-get static input: %s", error);
			proxy_client_fail(worker);
			return FALSE;
		}
		worker->msg_get_data.input =
			i_stream_create_dot(worker->input, FALSE);
		i_stream_set_destroy_callback(worker->msg_get_data.input,
					      proxy_client_worker_msg_get_done,
					      worker);
		io_remove(&worker->io);
		result = DSYNC_MSG_GET_RESULT_SUCCESS;
		break;
	case '0':
		/* expunged */
		result = DSYNC_MSG_GET_RESULT_EXPUNGED;
		break;
	default:
		/* failure */
		break;
	}

	request->callback.get(result, &worker->msg_get_data, request->context);
	return worker->io != NULL && worker->msg_get_data.input == NULL;
}

static void
proxy_client_worker_next_finish(struct proxy_client_dsync_worker *worker,
				const struct proxy_client_request *request,
				const char *line)
{
	bool success = TRUE;

	i_assert(worker->finishing);
	i_assert(!worker->finished);

	worker->finishing = FALSE;
	worker->finished = TRUE;

	if (strcmp(line, "changes") == 0)
		worker->worker.unexpected_changes = TRUE;
	else if (strcmp(line, "fail") == 0)
		success = FALSE;
	else if (strcmp(line, "ok") != 0) {
		i_error("Unexpected finish reply: %s", line);
		success = FALSE;
	}
		
	request->callback.finish(success, request->context);
}

static bool
proxy_client_worker_next_reply(struct proxy_client_dsync_worker *worker,
			       const char *line)
{
	const struct proxy_client_request *requests;
	struct proxy_client_request request;
	bool ret = TRUE;

	i_assert(worker->msg_get_data.input == NULL);

	if (aqueue_count(worker->request_queue) == 0) {
		i_error("Unexpected reply from server: %s", line);
		proxy_client_fail(worker);
		return FALSE;
	}

	requests = array_idx(&worker->request_array, 0);
	request = requests[aqueue_idx(worker->request_queue, 0)];
	aqueue_delete_tail(worker->request_queue);

	switch (request.type) {
	case PROXY_CLIENT_REQUEST_TYPE_COPY:
		ret = proxy_client_worker_next_copy(worker, &request, line);
		break;
	case PROXY_CLIENT_REQUEST_TYPE_GET:
		ret = proxy_client_worker_next_msg_get(worker, &request, line);
		break;
	case PROXY_CLIENT_REQUEST_TYPE_FINISH:
		proxy_client_worker_next_finish(worker, &request, line);
		break;
	}
	return ret;
}

static void proxy_client_worker_input(struct proxy_client_dsync_worker *worker)
{
	const char *line;
	int ret;

	if (worker->to_input != NULL)
		timeout_remove(&worker->to_input);

	if (worker->worker.input_callback != NULL) {
		worker->worker.input_callback(worker->worker.input_context);
		timeout_reset(worker->to);
		return;
	}

	while ((ret = proxy_client_worker_read_line(worker, &line)) > 0) {
		if (!proxy_client_worker_next_reply(worker, line))
			break;
	}
	if (ret < 0) {
		/* try to continue */
		proxy_client_worker_next_reply(worker, "");
	}

	if (worker->to_input != NULL) {
		/* input stream's destroy callback was already called.
		   don't get back here. */
		timeout_remove(&worker->to_input);
	}
	timeout_reset(worker->to);
}

static int
proxy_client_worker_output_real(struct proxy_client_dsync_worker *worker)
{
	int ret;

	if ((ret = o_stream_flush(worker->output)) < 0)
		return 1;

	if (worker->save_input != NULL) {
		/* proxy_client_worker_msg_save() hasn't finished yet. */
		o_stream_cork(worker->output);
		proxy_client_send_stream(worker);
		if (worker->save_input != NULL) {
			/* still unfinished, make sure we get called again */
			return 0;
		}
	}

	if (worker->worker.output_callback != NULL)
		worker->worker.output_callback(worker->worker.output_context);
	return ret;
}

static int proxy_client_worker_output(struct proxy_client_dsync_worker *worker)
{
	int ret;

	ret = proxy_client_worker_output_real(worker);
	timeout_reset(worker->to);
	return ret;
}

static void
proxy_client_worker_timeout(struct proxy_client_dsync_worker *worker)
{
	const char *reason;

	if (worker->save_io != NULL)
		reason = " (waiting for more input from mail being saved)";
	else if (worker->save_input != NULL) {
		size_t bytes = o_stream_get_buffer_used_size(worker->output);

		reason = t_strdup_printf(" (waiting for output stream to flush, "
					 "%"PRIuSIZE_T" bytes left)", bytes);
	} else if (worker->msg_get_data.input != NULL) {
		reason = " (waiting for MSG-GET message from remote)";
	} else {
		reason = "";
	}
	i_error("proxy client timed out%s", reason);
	proxy_client_fail(worker);
}

struct dsync_worker *dsync_worker_init_proxy_client(int fd_in, int fd_out)
{
	struct proxy_client_dsync_worker *worker;

	worker = i_new(struct proxy_client_dsync_worker, 1);
	worker->worker.v = proxy_client_dsync_worker;
	worker->fd_in = fd_in;
	worker->fd_out = fd_out;
	worker->to = timeout_add(DSYNC_PROXY_CLIENT_TIMEOUT_MSECS,
				 proxy_client_worker_timeout, worker);
	worker->io = io_add(fd_in, IO_READ, proxy_client_worker_input, worker);
	worker->input = i_stream_create_fd(fd_in, (size_t)-1, FALSE);
	worker->output = o_stream_create_fd(fd_out, (size_t)-1, FALSE);
	o_stream_send_str(worker->output, DSYNC_PROXY_CLIENT_GREETING_LINE"\n");
	/* we'll keep the output corked until flush is needed */
	o_stream_cork(worker->output);
	o_stream_set_flush_callback(worker->output, proxy_client_worker_output,
				    worker);
	fd_set_nonblock(fd_in, TRUE);
	fd_set_nonblock(fd_out, TRUE);

	worker->pending_commands = str_new(default_pool, 1024);
	worker->msg_get_pool = pool_alloconly_create("dsync proxy msg", 128);
	i_array_init(&worker->request_array, 64);
	worker->request_queue = aqueue_init(&worker->request_array.arr);

	return &worker->worker;
}

static void proxy_client_worker_deinit(struct dsync_worker *_worker)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	timeout_remove(&worker->to);
	if (worker->to_input != NULL)
		timeout_remove(&worker->to_input);
	if (worker->io != NULL)
		io_remove(&worker->io);
	i_stream_destroy(&worker->input);
	o_stream_destroy(&worker->output);
	if (close(worker->fd_in) < 0)
		i_error("close(worker input) failed: %m");
	if (worker->fd_in != worker->fd_out) {
		if (close(worker->fd_out) < 0)
			i_error("close(worker output) failed: %m");
	}
	aqueue_deinit(&worker->request_queue);
	array_free(&worker->request_array);
	pool_unref(&worker->msg_get_pool);
	str_free(&worker->pending_commands);
	i_free(worker);
}

static bool
worker_is_output_stream_full(struct proxy_client_dsync_worker *worker)
{
	return o_stream_get_buffer_used_size(worker->output) >=
		OUTBUF_THROTTLE_SIZE;
}

static bool proxy_client_worker_is_output_full(struct dsync_worker *_worker)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	if (worker->save_input != NULL) {
		/* we haven't finished sending a message save, so we're full. */
		return TRUE;
	}
	return worker_is_output_stream_full(worker);
}

static int proxy_client_worker_output_flush(struct dsync_worker *_worker)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;
	int ret = 1;

	if (o_stream_flush(worker->output) < 0)
		return -1;

	o_stream_uncork(worker->output);
	if (o_stream_get_buffer_used_size(worker->output) > 0)
		return 0;

	if (o_stream_send(worker->output, str_data(worker->pending_commands),
			  str_len(worker->pending_commands)) < 0)
		ret = -1;
	str_truncate(worker->pending_commands, 0);
	o_stream_cork(worker->output);
	return ret;
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
	o_stream_send_str(worker->output, "BOX-LIST\n");
	(void)proxy_client_worker_output_flush(_worker);
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

	if ((line[0] == '+' || line[0] == '-') && line[1] == '\0') {
		/* end of mailboxes */
		if (line[0] == '-') {
			i_error("Worker server's mailbox iteration failed");
			_iter->failed = TRUE;
		}
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

static struct dsync_worker_subs_iter *
proxy_client_worker_subs_iter_init(struct dsync_worker *_worker)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;
	struct proxy_client_dsync_worker_subs_iter *iter;

	iter = i_new(struct proxy_client_dsync_worker_subs_iter, 1);
	iter->iter.worker = _worker;
	iter->pool = pool_alloconly_create("proxy subscription iter", 1024);
	o_stream_send_str(worker->output, "SUBS-LIST\n");
	(void)proxy_client_worker_output_flush(_worker);
	return &iter->iter;
}

static int
proxy_client_worker_subs_iter_next_line(struct proxy_client_dsync_worker_subs_iter *iter,
					unsigned int wanted_arg_count,
					char ***args_r)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)iter->iter.worker;
	const char *line;
	char **args;
	int ret;

	if ((ret = proxy_client_worker_read_line(worker, &line)) <= 0) {
		if (ret < 0)
			iter->iter.failed = TRUE;
		return ret;
	}

	if ((line[0] == '+' || line[0] == '-') && line[1] == '\0') {
		/* end of subscribed subscriptions */
		if (line[0] == '-') {
			i_error("Worker server's subscription iteration failed");
			iter->iter.failed = TRUE;
		}
		return -1;
	}

	p_clear(iter->pool);
	args = p_strsplit(iter->pool, line, "\t");
	if (str_array_length((const char *const *)args) < wanted_arg_count) {
		i_error("Invalid subscription input from worker server");
		iter->iter.failed = TRUE;
		return -1;
	}
	*args_r = args;
	return 1;
}

static int
proxy_client_worker_subs_iter_next(struct dsync_worker_subs_iter *_iter,
				   struct dsync_worker_subscription *rec_r)
{
	struct proxy_client_dsync_worker_subs_iter *iter =
		(struct proxy_client_dsync_worker_subs_iter *)_iter;
	char **args;
	int ret;

	ret = proxy_client_worker_subs_iter_next_line(iter, 4, &args);
	if (ret <= 0)
		return ret;

	rec_r->vname = str_tabunescape(args[0]);
	rec_r->storage_name = str_tabunescape(args[1]);
	rec_r->ns_prefix = str_tabunescape(args[2]);
	rec_r->last_change = strtoul(args[3], NULL, 10);
	return 1;
}

static int
proxy_client_worker_subs_iter_next_un(struct dsync_worker_subs_iter *_iter,
				      struct dsync_worker_unsubscription *rec_r)
{
	struct proxy_client_dsync_worker_subs_iter *iter =
		(struct proxy_client_dsync_worker_subs_iter *)_iter;
	char **args;
	int ret;

	ret = proxy_client_worker_subs_iter_next_line(iter, 3, &args);
	if (ret <= 0)
		return ret;

	memset(rec_r, 0, sizeof(*rec_r));
	if (dsync_proxy_mailbox_guid_import(args[0], &rec_r->name_sha1) < 0) {
		i_error("Invalid subscription input from worker server: "
			"Invalid unsubscription mailbox GUID");
		iter->iter.failed = TRUE;
		return -1;
	}
	rec_r->ns_prefix = str_tabunescape(args[1]);
	rec_r->last_change = strtoul(args[2], NULL, 10);
	return 1;
}

static int
proxy_client_worker_subs_iter_deinit(struct dsync_worker_subs_iter *_iter)
{
	struct proxy_client_dsync_worker_subs_iter *iter =
		(struct proxy_client_dsync_worker_subs_iter *)_iter;
	int ret = _iter->failed ? -1 : 0;

	pool_unref(&iter->pool);
	i_free(iter);
	return ret;
}

static void
proxy_client_worker_set_subscribed(struct dsync_worker *_worker,
				   const char *name, time_t last_change,
				   bool set)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_append(str, "SUBS-SET\t");
		str_tabescape_write(str, name);
		str_printfa(str, "\t%s\t%d\n", dec2str(last_change),
			    set ? 1 : 0);
		o_stream_send(worker->output, str_data(str), str_len(str));
	} T_END;
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
	iter->pool = pool_alloconly_create("proxy message iter", 10240);

	str = str_new(iter->pool, 512);
	str_append(str, "MSG-LIST");
	for (i = 0; i < mailbox_count; i++) T_BEGIN {
		str_append_c(str, '\t');
		dsync_proxy_mailbox_guid_export(str, &mailboxes[i]);
	} T_END;
	str_append_c(str, '\n');
	o_stream_send(worker->output, str_data(str), str_len(str));
	p_clear(iter->pool);

	(void)proxy_client_worker_output_flush(_worker);
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

	if ((line[0] == '+' || line[0] == '-') && line[1] == '\0') {
		/* end of messages */
		if (line[0] == '-') {
			i_error("Worker server's message iteration failed");
			_iter->failed = TRUE;
		}
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
proxy_client_worker_cmd(struct proxy_client_dsync_worker *worker, string_t *str)
{
	if (worker->save_input == NULL)
		o_stream_send(worker->output, str_data(str), str_len(str));
	else
		str_append_str(worker->pending_commands, str);
}

static void
proxy_client_worker_create_mailbox(struct dsync_worker *_worker,
				   const struct dsync_mailbox *dsync_box)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_append(str, "BOX-CREATE\t");
		dsync_proxy_mailbox_export(str, dsync_box);
		str_append_c(str, '\n');
		proxy_client_worker_cmd(worker, str);
	} T_END;
}

static void
proxy_client_worker_delete_mailbox(struct dsync_worker *_worker,
				   const struct dsync_mailbox *dsync_box)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_append(str, "BOX-DELETE\t");
		dsync_proxy_mailbox_guid_export(str, &dsync_box->mailbox_guid);
		str_printfa(str, "\t%s\n", dec2str(dsync_box->last_change));
		proxy_client_worker_cmd(worker, str);
	} T_END;
}

static void
proxy_client_worker_delete_dir(struct dsync_worker *_worker,
			       const struct dsync_mailbox *dsync_box)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_append(str, "DIR-DELETE\t");
		str_tabescape_write(str, dsync_box->name);
		str_printfa(str, "\t%s\n", dec2str(dsync_box->last_change));
		proxy_client_worker_cmd(worker, str);
	} T_END;
}

static void
proxy_client_worker_rename_mailbox(struct dsync_worker *_worker,
				   const mailbox_guid_t *mailbox,
				   const struct dsync_mailbox *dsync_box)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;
	char sep[2];

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_append(str, "BOX-RENAME\t");
		dsync_proxy_mailbox_guid_export(str, mailbox);
		str_append_c(str, '\t');
		str_tabescape_write(str, dsync_box->name);
		str_append_c(str, '\t');
		sep[0] = dsync_box->name_sep; sep[1] = '\0';
		str_tabescape_write(str, sep);
		str_append_c(str, '\n');
		proxy_client_worker_cmd(worker, str);
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

		str_append(str, "BOX-UPDATE\t");
		dsync_proxy_mailbox_export(str, dsync_box);
		str_append_c(str, '\n');
		proxy_client_worker_cmd(worker, str);
	} T_END;
}

static void
proxy_client_worker_select_mailbox(struct dsync_worker *_worker,
				   const mailbox_guid_t *mailbox,
				   const ARRAY_TYPE(const_string) *cache_fields)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	if (dsync_guid_equals(&worker->selected_box_guid, mailbox))
		return;
	worker->selected_box_guid = *mailbox;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_append(str, "BOX-SELECT\t");
		dsync_proxy_mailbox_guid_export(str, mailbox);
		if (cache_fields != NULL)
			dsync_proxy_strings_export(str, cache_fields);
		str_append_c(str, '\n');
		proxy_client_worker_cmd(worker, str);
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

		str_printfa(str, "MSG-UPDATE\t%u\t%llu\t", msg->uid,
			    (unsigned long long)msg->modseq);
		imap_write_flags(str, msg->flags, msg->keywords);
		str_append_c(str, '\n');
		proxy_client_worker_cmd(worker, str);
	} T_END;
}

static void
proxy_client_worker_msg_update_uid(struct dsync_worker *_worker,
				   uint32_t old_uid, uint32_t new_uid)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		string_t *str = t_str_new(64);
		str_printfa(str, "MSG-UID-CHANGE\t%u\t%u\n", old_uid, new_uid);
		proxy_client_worker_cmd(worker, str);
	} T_END;
}

static void
proxy_client_worker_msg_expunge(struct dsync_worker *_worker, uint32_t uid)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		string_t *str = t_str_new(64);
		str_printfa(str, "MSG-EXPUNGE\t%u\n", uid);
		proxy_client_worker_cmd(worker, str);
	} T_END;
}

static void
proxy_client_worker_msg_copy(struct dsync_worker *_worker,
			     const mailbox_guid_t *src_mailbox,
			     uint32_t src_uid,
			     const struct dsync_message *dest_msg,
			     dsync_worker_copy_callback_t *callback,
			     void *context)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;
	struct proxy_client_request request;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_append(str, "MSG-COPY\t");
		dsync_proxy_mailbox_guid_export(str, src_mailbox);
		str_printfa(str, "\t%u\t", src_uid);
		dsync_proxy_msg_export(str, dest_msg);
		str_append_c(str, '\n');
		proxy_client_worker_cmd(worker, str);
	} T_END;

	memset(&request, 0, sizeof(request));
	request.type = PROXY_CLIENT_REQUEST_TYPE_COPY;
	request.callback.copy = callback;
	request.context = context;
	request.uid = src_uid;
	aqueue_append(worker->request_queue, &request);
}

static void
proxy_client_send_stream_real(struct proxy_client_dsync_worker *worker)
{
	dsync_worker_save_callback_t *callback;
	void *context;
	struct istream *input;
	const unsigned char *data;
	size_t size;
	int ret;

	while ((ret = i_stream_read_data(worker->save_input,
					 &data, &size, 0)) > 0) {
		dsync_proxy_send_dot_output(worker->output,
					    &worker->save_input_last_lf,
					    data, size);
		i_stream_skip(worker->save_input, size);

		if (worker_is_output_stream_full(worker)) {
			o_stream_uncork(worker->output);
			if (worker_is_output_stream_full(worker))
				return;
			o_stream_cork(worker->output);
		}
	}
	if (ret == 0) {
		/* waiting for more input */
		o_stream_uncork(worker->output);
		if (worker->save_io == NULL) {
			int fd = i_stream_get_fd(worker->save_input);

			worker->save_io =
				io_add(fd, IO_READ,
				       proxy_client_send_stream, worker);
		}
		return;
	}
	if (worker->save_io != NULL)
		io_remove(&worker->save_io);
	if (worker->save_input->stream_errno != 0) {
		errno = worker->save_input->stream_errno;
		i_error("proxy: reading message input failed: %m");
		o_stream_close(worker->output);
	} else {
		i_assert(!i_stream_have_bytes_left(worker->save_input));
		o_stream_send(worker->output, "\n.\n", 3);
	}

	callback = worker->save_callback;
	context = worker->save_context;
	worker->save_callback = NULL;
	worker->save_context = NULL;

	/* a bit ugly way to free the stream. the problem is that local worker
	   has set a destroy callback, which in turn can call our msg_save()
	   again before the i_stream_unref() is finished. */
	input = worker->save_input;
	worker->save_input = NULL;
	i_stream_unref(&input);

	(void)proxy_client_worker_output_flush(&worker->worker);

	callback(context);
}

static void proxy_client_send_stream(struct proxy_client_dsync_worker *worker)
{
	proxy_client_send_stream_real(worker);
	timeout_reset(worker->to);
}

static void
proxy_client_worker_msg_save(struct dsync_worker *_worker,
			     const struct dsync_message *msg,
			     const struct dsync_msg_static_data *data,
			     dsync_worker_save_callback_t *callback,
			     void *context)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_append(str, "MSG-SAVE\t");
		dsync_proxy_msg_static_export(str, data);
		str_append_c(str, '\t');
		dsync_proxy_msg_export(str, msg);
		str_append_c(str, '\n');
		proxy_client_worker_cmd(worker, str);
	} T_END;

	i_assert(worker->save_input == NULL);
	worker->save_callback = callback;
	worker->save_context = context;
	worker->save_input = data->input;
	worker->save_input_last_lf = TRUE;
	i_stream_ref(worker->save_input);
	proxy_client_send_stream(worker);
}

static void
proxy_client_worker_msg_save_cancel(struct dsync_worker *_worker)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;

	if (worker->save_io != NULL)
		io_remove(&worker->save_io);
	if (worker->save_input != NULL)
		i_stream_unref(&worker->save_input);
}

static void
proxy_client_worker_msg_get(struct dsync_worker *_worker,
			    const mailbox_guid_t *mailbox, uint32_t uid,
			    dsync_worker_msg_callback_t *callback,
			    void *context)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;
	struct proxy_client_request request;

	T_BEGIN {
		string_t *str = t_str_new(128);

		str_append(str, "MSG-GET\t");
		dsync_proxy_mailbox_guid_export(str, mailbox);
		str_printfa(str, "\t%u\n", uid);
		proxy_client_worker_cmd(worker, str);
	} T_END;

	memset(&request, 0, sizeof(request));
	request.type = PROXY_CLIENT_REQUEST_TYPE_GET;
	request.callback.get = callback;
	request.context = context;
	request.uid = uid;
	aqueue_append(worker->request_queue, &request);
}

static void
proxy_client_worker_finish(struct dsync_worker *_worker,
			   dsync_worker_finish_callback_t *callback,
			   void *context)
{
	struct proxy_client_dsync_worker *worker =
		(struct proxy_client_dsync_worker *)_worker;
	struct proxy_client_request request;

	i_assert(worker->save_input == NULL);
	i_assert(!worker->finishing);

	worker->finishing = TRUE;
	worker->finished = FALSE;

	o_stream_send_str(worker->output, "FINISH\n");
	o_stream_uncork(worker->output);

	memset(&request, 0, sizeof(request));
	request.type = PROXY_CLIENT_REQUEST_TYPE_FINISH;
	request.callback.finish = callback;
	request.context = context;
	aqueue_append(worker->request_queue, &request);
}

struct dsync_worker_vfuncs proxy_client_dsync_worker = {
	proxy_client_worker_deinit,

	proxy_client_worker_is_output_full,
	proxy_client_worker_output_flush,

	proxy_client_worker_mailbox_iter_init,
	proxy_client_worker_mailbox_iter_next,
	proxy_client_worker_mailbox_iter_deinit,

	proxy_client_worker_subs_iter_init,
	proxy_client_worker_subs_iter_next,
	proxy_client_worker_subs_iter_next_un,
	proxy_client_worker_subs_iter_deinit,
	proxy_client_worker_set_subscribed,

	proxy_client_worker_msg_iter_init,
	proxy_client_worker_msg_iter_next,
	proxy_client_worker_msg_iter_deinit,

	proxy_client_worker_create_mailbox,
	proxy_client_worker_delete_mailbox,
	proxy_client_worker_delete_dir,
	proxy_client_worker_rename_mailbox,
	proxy_client_worker_update_mailbox,

	proxy_client_worker_select_mailbox,
	proxy_client_worker_msg_update_metadata,
	proxy_client_worker_msg_update_uid,
	proxy_client_worker_msg_expunge,
	proxy_client_worker_msg_copy,
	proxy_client_worker_msg_save,
	proxy_client_worker_msg_save_cancel,
	proxy_client_worker_msg_get,
	proxy_client_worker_finish
};
