/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "guid.h"
#include "llist.h"
#include "master-service.h"
#include "dict.h"
#include "fs-api.h"

#define DEFAULT_MAX_PARALLEL_OPS 30
#define DEFAULT_FILES_COUNT 100
/* Allow +-10% difference in number of files */
#define FILES_COUNT_APPROX 0.9

struct test_read {
	struct test_read *prev, *next;

	struct test_ctx *ctx;
	struct fs_file *file;
	struct istream *input;
	struct io *io;
};

struct test_write {
	struct test_write *prev, *next;

	struct test_ctx *ctx;
	struct fs_file *file;
};

struct test_delete {
	struct test_delete *prev, *next;

	struct test_ctx *ctx;
	struct fs_file *file;
};

struct test_iter {
	struct test_iter *prev, *next;

	struct test_ctx *ctx;
	pool_t pool;
	ARRAY_TYPE(const_string) files;
	struct fs_iter *iter;
	bool object_ids;
};

struct test_ctx {
	struct fs *fs;
	const char *prefix;
	bool sync_only, async_only;
	unsigned int files_count;
	unsigned int max_parallel_ops;

	pool_t files_pool;
	ARRAY_TYPE(const_string) files;

	struct timeout *to;
	struct test_read *reads;
	struct test_write *writes;
	struct test_delete *deletes;
	struct test_iter *iters;
	unsigned int running_op_count;

	unsigned int total_reads, total_writes, total_deletes, total_iters;
};

static struct ioloop *root_ioloop;

static void test_more(struct test_ctx *ctx);
static void test_read_callback(struct test_read *r);

static bool test_want_async(struct test_ctx *ctx)
{
	if (ctx->async_only)
		return TRUE;
	if (ctx->sync_only)
		return FALSE;
	return (i_rand_limit(2) == 0);
}

static void test_op_finish(struct test_ctx *ctx)
{
	i_assert(ctx->running_op_count > 0);
	ctx->running_op_count--;

	if (ctx->to == NULL)
		ctx->to = timeout_add_short_to(root_ioloop, 0, test_more, ctx);
}

static void test_write_finish(struct test_write *w)
{
	DLLIST_REMOVE(&w->ctx->writes, w);
	fs_file_deinit(&w->file);

	w->ctx->total_writes++;
	test_op_finish(w->ctx);
	i_free(w);
}

static void test_write_callback(struct test_write *w)
{
	int ret;

	ret = fs_write_stream_finish_async(w->file);
	if (ret < 0) {
		i_error("fs_write_stream() failed: %s",
			fs_file_last_error(w->file));
	}
	if (ret != 0)
		test_write_finish(w);
}

static void test_next_op_write(struct test_ctx *ctx)
{
	struct test_write *w;
	struct istream *input, *input2;
	struct ostream *output;
	const char *path;

	w = i_new(struct test_write, 1);
	w->ctx = ctx;
	DLLIST_PREPEND(&ctx->writes, w);

	path = t_strconcat(ctx->prefix, guid_generate(), NULL);
	w->file = fs_file_init(ctx->fs, path, FS_OPEN_MODE_REPLACE |
			       (test_want_async(ctx) ? FS_OPEN_FLAG_ASYNC : 0));
	input = i_stream_create_file("/dev/urandom", IO_BLOCK_SIZE);
	input2 = i_stream_create_limit(input, i_rand_limit(1024*1024));
	output = fs_write_stream(w->file);
	switch (o_stream_send_istream(output, input2)) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		break;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		i_unreached();
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		i_fatal("read(/dev/urandom) failed: %s",
			i_stream_get_error(input));
		case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
			i_fatal("write() failed: %s",
				o_stream_get_error(output));
	}
	i_stream_unref(&input);
	i_stream_unref(&input2);

	int ret = fs_write_stream_finish(w->file, &output);
	if (ret < 0) {
		i_error("fs_write_stream(%s) failed: %s",
			path, fs_file_last_error(w->file));
	}
	if (ret == 0)
		fs_file_set_async_callback(w->file, test_write_callback, w);
	else
		test_write_finish(w);
}

static void test_iter_finish(struct test_iter *i)
{
	const char *error;

	DLLIST_REMOVE(&i->ctx->iters, i);

	if (fs_iter_deinit(&i->iter, &error) < 0) {
		i_error("fs_iter_deinit() failed: %s", error);
		pool_unref(&i->pool);
	} else {
		pool_unref(&i->ctx->files_pool);
		i->ctx->files_pool = i->pool;
		i->ctx->files = i->files;
	}

	i->ctx->total_iters++;
	test_op_finish(i->ctx);
	i_free(i);
}

static void test_iter_callback(struct test_iter *i)
{
	const char *fname;

	while ((fname = fs_iter_next(i->iter)) != NULL) {
		if (i->object_ids) {
			/* skip object ID */
			fname = strchr(fname, '/');
			i_assert(fname != NULL);
			fname++;
		}
		fname = p_strdup(i->pool, fname);
		array_push_back(&i->files, &fname);
	}

	if (!fs_iter_have_more(i->iter))
		test_iter_finish(i);
}

static void test_next_op_iter(struct test_ctx *ctx)
{
	struct test_iter *i;

	i = i_new(struct test_iter, 1);
	i->ctx = ctx;
	i->pool = pool_alloconly_create(MEMPOOL_GROWING"test iter", 256);
	p_array_init(&i->files, i->pool, 16);
	DLLIST_PREPEND(&ctx->iters, i);

	i->object_ids = (fs_get_properties(ctx->fs) &
			 FS_PROPERTY_OBJECTIDS) == 0 ?
		FALSE : (i_rand_limit(2) == 0);
	i->iter = fs_iter_init(ctx->fs, ctx->prefix,
			       (test_want_async(ctx) ? FS_ITER_FLAG_ASYNC : 0) |
			       (i->object_ids ? FS_ITER_FLAG_OBJECTIDS : 0));
	fs_iter_set_async_callback(i->iter, test_iter_callback, i);
	test_iter_callback(i);
}

static void test_read_finish(struct test_read *r)
{
	DLLIST_REMOVE(&r->ctx->reads, r);
	io_remove(&r->io);
	i_stream_unref(&r->input);
	fs_file_deinit(&r->file);

	r->ctx->total_reads++;
	test_op_finish(r->ctx);
	i_free(r);
}

static void test_read_callback(struct test_read *r)
{
	const unsigned char *data;
	size_t size;
	int ret;

	while ((ret = i_stream_read_more(r->input, &data, &size)) > 0)
		i_stream_skip(r->input, size);
	if (ret == 0) {
		if (r->io == NULL) {
			r->io = io_add_istream(r->input, test_read_callback, r);
			fs_file_set_async_callback(r->file, test_read_callback, r);
		}
		return;
	}
	i_assert(ret == -1);
	if (r->input->stream_errno != 0 &&
	    r->input->stream_errno != ENOENT)
		i_error("read() failed: %s", i_stream_get_error(r->input));
	test_read_finish(r);
}

static void test_next_read(struct test_ctx *ctx)
{
	struct test_read *r;

	r = i_new(struct test_read, 1);
	r->ctx = ctx;
	DLLIST_PREPEND(&ctx->reads, r);

	const char *const *fnamep =
		array_idx(&ctx->files, i_rand_limit(array_count(&ctx->files)));
	const char *path = t_strconcat(ctx->prefix, *fnamep, NULL);
	r->file = fs_file_init(ctx->fs, path, FS_OPEN_MODE_READONLY |
			       (test_want_async(ctx) ? FS_OPEN_FLAG_ASYNC : 0));
	r->input = fs_read_stream(r->file, IO_BLOCK_SIZE);
	test_read_callback(r);
}

static void test_delete_finish(struct test_delete *d)
{
	DLLIST_REMOVE(&d->ctx->deletes, d);
	fs_file_deinit(&d->file);

	d->ctx->total_deletes++;
	test_op_finish(d->ctx);
	i_free(d);
}

static void test_delete_callback(struct test_delete *d)
{
	int ret = fs_delete(d->file);
	if (ret < 0 && errno != ENOENT) {
		if (errno == EAGAIN)
			return;
		i_error("fs_delete() failed: %s", fs_file_last_error(d->file));
	}
	test_delete_finish(d);
}

static void test_next_delete(struct test_ctx *ctx)
{
	struct test_delete *d;

	d = i_new(struct test_delete, 1);
	d->ctx = ctx;
	DLLIST_PREPEND(&ctx->deletes, d);

	const char *const *fnamep =
		array_idx(&ctx->files, i_rand_limit(array_count(&ctx->files)));
	const char *path = t_strconcat(ctx->prefix, *fnamep, NULL);
	d->file = fs_file_init(ctx->fs, path, FS_OPEN_MODE_READONLY |
			       (test_want_async(ctx) ? FS_OPEN_FLAG_ASYNC : 0));
	int ret = fs_delete(d->file);
	if (ret < 0 && errno == EAGAIN) {
		fs_file_set_async_callback(d->file, test_delete_callback, d);
		return;
	}
	if (ret < 0 && errno != ENOENT)
		i_error("fs_delete() failed: %s", fs_file_last_error(d->file));
	test_delete_finish(d);
}

static void test_next_op(struct test_ctx *ctx)
{
	switch (i_rand_limit(4)) {
	case 0:
		if (array_is_created(&ctx->files) &&
		    array_count(&ctx->files) * FILES_COUNT_APPROX > ctx->files_count)
			break;
		ctx->running_op_count++;
		test_next_op_write(ctx);
		break;
	case 1:
		ctx->running_op_count++;
		test_next_op_iter(ctx);
		break;
	case 2:
		if (!array_is_created(&ctx->files) ||
		    array_count(&ctx->files) == 0)
			break;
		ctx->running_op_count++;
		test_next_read(ctx);
		break;
	case 3:
		if (!array_is_created(&ctx->files) ||
		    array_count(&ctx->files) / FILES_COUNT_APPROX < ctx->files_count)
			break;
		ctx->running_op_count++;
		test_next_delete(ctx);
		break;
	}
}

static void test_more(struct test_ctx *ctx)
{
	timeout_remove(&ctx->to);
	/* note that all operations may be synchronous */
	for (unsigned int i = ctx->running_op_count; i < ctx->max_parallel_ops; i++)
		test_next_op(ctx);
	if (ctx->to == NULL) {
		ctx->to = timeout_add(ctx->running_op_count == 0 ? 0 :
				      i_rand_limit(100), test_more, ctx);
	}
}

static void stats_output(struct test_ctx *ctx)
{
	printf("%u iters, %u reads, %u writes, %u deletes\n",
	       ctx->total_iters, ctx->total_reads, ctx->total_writes,
	       ctx->total_deletes);
}

int main(int argc, char *argv[])
{
	struct fs_settings set;
	struct test_ctx ctx;
	const char *error;
	unsigned int timeout_secs = 0;
	struct timeout *to_stop = NULL;
	int c;

	i_zero(&ctx);
	ctx.max_parallel_ops = DEFAULT_MAX_PARALLEL_OPS;
	ctx.files_count = DEFAULT_FILES_COUNT;

	i_zero(&set);
	set.base_dir = PKG_RUNDIR;
	master_service = master_service_init("test-fs",
					     MASTER_SERVICE_FLAG_STANDALONE,
					     &argc, &argv, "Daf:p:st:u:");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			set.debug = TRUE;
			break;
		case 'a':
			ctx.async_only = TRUE;
			break;
		case 'f':
			if (str_to_uint(optarg, &ctx.files_count) < 0)
				i_fatal("Invalid -f parameter: %s", optarg);
			break;
		case 'p':
			if (str_to_uint(optarg, &ctx.max_parallel_ops) < 0)
				i_fatal("Invalid -p parameter: %s", optarg);
			break;
		case 's':
			ctx.sync_only = TRUE;
			break;
		case 'u':
			set.username = optarg;
			break;
		case 't':
			if (str_to_uint(optarg, &timeout_secs) < 0)
				i_fatal("Invalid -t parameter: %s", optarg);
			break;
		default:
			return FATAL_DEFAULT;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 3)
		i_fatal("Usage: [-a|-s] [-D] [-f <files#>] [-p <max ops>] [-t <secs>] [-u <user>] <driver> <args> <prefix>");

	master_service_init_finish(master_service);
	dict_drivers_register_builtin();

	if (fs_init(argv[0], argv[1], &set, &ctx.fs, &error) < 0)
		i_fatal("fs_init() failed: %s", error);
	ctx.prefix = argv[2];

	root_ioloop = current_ioloop;
	test_more(&ctx);
	if (timeout_secs != 0)
		to_stop = timeout_add(timeout_secs*1000, io_loop_stop, current_ioloop);
	struct timeout *to_stats = timeout_add(1000, stats_output, &ctx);
	io_loop_run(current_ioloop);
	timeout_remove(&to_stats);
	timeout_remove(&to_stop);

	while (ctx.writes != NULL)
		test_write_finish(ctx.writes);
	while (ctx.iters != NULL)
		test_iter_finish(ctx.iters);
	while (ctx.reads != NULL)
		test_read_finish(ctx.reads);
	while (ctx.deletes != NULL)
		test_delete_finish(ctx.deletes);

	stats_output(&ctx);
	timeout_remove(&ctx.to);
	fs_deinit(&ctx.fs);
	master_service_deinit(&master_service);
}
