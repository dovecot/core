/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "read-full.h"
#include "write-full.h"
#include "unlink-directory.h"
#include "test-common.h"
#include "test-dir.h"
#include "test-corruption.h"
#include "master-service.h"
#include "mail-search-build.h"
#include "mailbox-list-iter.h"
#include "mail-index.h"
#include "mail-thread.h"
#include "test-mail-storage-common.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_USERNAME "testuser"
/* Accessing the storage is slow, so keep the number of corruptions small by
   default. Use TEST_CORRUPTION_* environment variables for more thorough
   testing. */
#define TEST_RANDOM_COUNT 30
#define TEST_MAX_DETERMINISTIC_COUNT 30

struct test_storage_file {
	/* relative to home */
	char *path;
	unsigned char *data;
	size_t size;
	bool dir;
};

struct test_storage_corruption_ctx {
	struct test_mail_storage_ctx *storage_ctx;
	const struct test_mail_storage_settings *set;
	const struct test_storage_file *file;
	const char *home;
};

static ARRAY(struct test_storage_file) test_files;
static failure_callback_t *orig_error_callback;

static const char *const test_mailboxes[] = {
	"Foo", "Foo/Bar", "Foo/Bar/Baz", "Trash", "Archive"
};

static void
test_ignore_errors_handler(const struct failure_context *ctx,
			   const char *format, va_list args)
{
	/* Corruption is expected to be logged as errors and warnings */
	if (ctx->type == LOG_TYPE_ERROR || ctx->type == LOG_TYPE_WARNING)
		return;
	orig_error_callback(ctx, format, args);
}

static int test_mail_save(struct mailbox *box, unsigned int n)
{
	struct mailbox_transaction_context *trans;
	struct mail_save_context *save_ctx;
	struct istream *input;
	int ret = -1;
	const char *mail_input = t_strdup_printf(
		"From: user@example.com\n"
		"Subject: %stest %u\n"
		"Message-ID: <%u@example.com>\n"
		"In-Reply-To: <%u@example.com>\n"
		"References: <%u@example.com> <%u@example.com>\n"
		"\n"
		"body %u\n", n % 2 == 0 ? "" : "Re: ", n / 2, n,
		n / 2, n / 4, n / 2, n);

	input = i_stream_create_from_data(mail_input, strlen(mail_input));
	trans = mailbox_transaction_begin(box,
			MAILBOX_TRANSACTION_FLAG_EXTERNAL, __func__);
	save_ctx = mailbox_save_alloc(trans);
	if (mailbox_save_begin(&save_ctx, input) < 0)
		mailbox_transaction_rollback(&trans);
	else {
		while (i_stream_read(input) > 0) ;
		if (mailbox_save_finish(&save_ctx) < 0)
			mailbox_transaction_rollback(&trans);
		else
			ret = mailbox_transaction_commit(&trans);
	}
	i_stream_unref(&input);
	return ret;
}

static void test_mailbox_read_mails(struct mailbox *box, bool expunge)
{
	struct mailbox_transaction_context *trans;
	struct mail_search_args *search_args;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	struct istream *input;
	const char *value;
	uoff_t size;

	trans = mailbox_transaction_begin(box, 0, __func__);
	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	search_ctx = mailbox_search_init(trans, search_args, NULL,
					 MAIL_FETCH_STREAM_BODY, NULL);
	mail_search_args_unref(&search_args);
	while (mailbox_search_next(search_ctx, &mail)) {
		(void)mail_get_first_header(mail, "Subject", &value);
		(void)mail_get_virtual_size(mail, &size);
		if (mail_get_stream(mail, NULL, NULL, &input) == 0) {
			while (i_stream_read(input) > 0)
				i_stream_skip(input, i_stream_get_data_size(input));
		}
		if (expunge && mail->seq == 1)
			mail_expunge(mail);
	}
	(void)mailbox_search_deinit(&search_ctx);
	(void)mailbox_transaction_commit(&trans);
}

static void
test_mail_thread_iterate(struct mail_thread_iterate_context *iter)
{
	struct mail_thread_iterate_context *child_iter;

	while (mail_thread_iterate_next(iter, &child_iter) != NULL) {
		if (child_iter != NULL)
			test_mail_thread_iterate(child_iter);
	}
	(void)mail_thread_iterate_deinit(&iter);
}

static void test_mailbox_thread(struct mailbox *box)
{
	static const enum mail_thread_type types[] = {
		MAIL_THREAD_REFERENCES, MAIL_THREAD_REFS,
	};
	struct mail_thread_context *ctx;

	if (mail_thread_init(box, NULL, &ctx) < 0)
		return;
	for (unsigned int i = 0; i < N_ELEMENTS(types); i++) {
		test_mail_thread_iterate(
			mail_thread_iterate_init(ctx, types[i], FALSE));
	}
	mail_thread_deinit(&ctx);
}

static void test_storage_access(struct mail_user *user, bool modify)
{
	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	struct mailbox_status status;
	struct mailbox *box;
	ARRAY_TYPE(const_string) names;

	/* list all mailboxes with their status */
	t_array_init(&names, 8);
	iter = mailbox_list_iter_init(ns->list, "*",
				      MAILBOX_LIST_ITER_RETURN_SUBSCRIBED |
				      MAILBOX_LIST_ITER_RETURN_CHILDREN);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		const char *name = t_strdup(info->vname);
		array_push_back(&names, &name);
	}
	(void)mailbox_list_iter_deinit(&iter);
	if (array_count(&names) == 0) {
		const char *inbox = "INBOX";
		array_push_back(&names, &inbox);
	}

	const char *name;
	array_foreach_elem(&names, name) {
		box = mailbox_alloc(ns->list, name, 0);
		(void)mailbox_get_status(box, STATUS_MESSAGES | STATUS_UNSEEN |
					 STATUS_UIDNEXT | STATUS_UIDVALIDITY |
					 STATUS_HIGHESTMODSEQ, &status);
		if (mailbox_open(box) == 0 &&
		    mailbox_sync(box, 0) == 0) {
			test_mailbox_thread(box);
			test_mailbox_read_mails(box, modify);
			if (modify) {
				(void)test_mail_save(box, 100);
				(void)mailbox_sync(box, 0);
				test_mailbox_thread(box);
			}
		}
		mailbox_free(&box);
	}
	if (!modify)
		return;

	/* modify the mailbox list */
	box = mailbox_alloc(ns->list, "NewBox", 0);
	(void)mailbox_create(box, NULL, FALSE);
	(void)mailbox_set_subscribed(box, TRUE);
	mailbox_free(&box);

	struct mailbox *src = mailbox_alloc(ns->list, "Archive", 0);
	struct mailbox *dest = mailbox_alloc(ns->list, "Archive2", 0);
	(void)mailbox_rename(src, dest);
	mailbox_free(&src);
	mailbox_free(&dest);

	box = mailbox_alloc(ns->list, "Trash", 0);
	(void)mailbox_delete(box);
	mailbox_free(&box);

	(void)mail_storage_purge(ns->storage);
}

static void
test_storage_create(struct test_mail_storage_ctx *ctx,
		    const struct test_mail_storage_settings *set)
{
	struct mail_namespace *ns;
	struct mailbox *box;

	test_mail_storage_init_user(ctx, set);
	ns = mail_namespace_find_inbox(ctx->user->namespaces);

	box = mailbox_alloc(ns->list, "INBOX", 0);
	test_assert(mailbox_open(box) == 0);
	for (unsigned int i = 0; i < 10; i++)
		test_assert(test_mail_save(box, i) == 0);
	test_assert(mailbox_sync(box, 0) == 0);
	mailbox_free(&box);

	for (unsigned int i = 0; i < N_ELEMENTS(test_mailboxes); i++) {
		box = mailbox_alloc(ns->list, test_mailboxes[i], 0);
		test_assert(mailbox_create(box, NULL, FALSE) == 0);
		test_assert(mailbox_set_subscribed(box, TRUE) == 0);
		test_assert(mailbox_open(box) == 0);
		test_assert(test_mail_save(box, i) == 0);
		test_assert(mailbox_sync(box, 0) == 0);
		mailbox_free(&box);
	}
	/* expunge a mail and update the list index status */
	test_storage_access(ctx->user, FALSE);
	box = mailbox_alloc(ns->list, "INBOX", 0);
	test_assert(mailbox_open(box) == 0);
	test_mailbox_read_mails(box, TRUE);
	test_assert(mailbox_sync(box, 0) == 0);
	mailbox_free(&box);
	test_storage_access(ctx->user, FALSE);

	test_mail_storage_deinit_user(ctx);
}

static const char *test_storage_find_file(const char *dir, const char *fname)
{
	const char *path, *found = NULL;
	struct dirent *d;
	struct stat st;
	DIR *dirp;

	dirp = opendir(dir);
	if (dirp == NULL)
		i_fatal("opendir(%s) failed: %m", dir);
	while (found == NULL && (d = readdir(dirp)) != NULL) {
		if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
			continue;
		path = t_strdup_printf("%s/%s", dir, d->d_name);
		if (lstat(path, &st) < 0)
			i_fatal("lstat(%s) failed: %m", path);
		if (S_ISDIR(st.st_mode))
			found = test_storage_find_file(path, fname);
		else if (strcmp(d->d_name, fname) == 0)
			found = dir;
	}
	if (closedir(dirp) < 0)
		i_fatal("closedir(%s) failed: %m", dir);
	return found;
}

/* Make sure the index file is written, not just the transaction log. The
   prefix is either a path relative to home or a filename that is searched
   from home. */
static void test_storage_index_write(const char *home, const char *prefix)
{
	struct mail_index *index;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	const char *dir, *p;

	p = strrchr(prefix, '/');
	if (p != NULL) {
		dir = t_strdup_printf("%s/%s", home,
				      t_strdup_until(prefix, p));
		prefix = p + 1;
	} else {
		dir = test_storage_find_file(home,
					     t_strconcat(prefix, ".log", NULL));
		if (dir == NULL)
			i_fatal("%s.log not found", prefix);
	}

	index = mail_index_alloc(NULL, dir, prefix);
	test_assert(mail_index_open(index, 0) > 0);
	test_assert(mail_index_sync_begin(index, &sync_ctx, &view,
					  &trans, 0) > 0);
	mail_index_write(index, FALSE, "test");
	test_assert(mail_index_sync_commit(&sync_ctx) == 0);
	mail_index_close(index);
	mail_index_free(&index);
}

static void
test_storage_files_read_dir(const char *home, const char *relpath)
{
	const char *dir = relpath[0] == '\0' ? home :
		t_strdup_printf("%s/%s", home, relpath);
	struct test_storage_file *file;
	struct dirent *d;
	struct stat st;
	DIR *dirp;

	dirp = opendir(dir);
	if (dirp == NULL)
		i_fatal("opendir(%s) failed: %m", dir);
	while ((d = readdir(dirp)) != NULL) {
		if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
			continue;
		const char *file_relpath = relpath[0] == '\0' ? d->d_name :
			t_strdup_printf("%s/%s", relpath, d->d_name);
		const char *path = t_strdup_printf("%s/%s", home, file_relpath);
		if (lstat(path, &st) < 0)
			i_fatal("lstat(%s) failed: %m", path);

		file = array_append_space(&test_files);
		file->path = i_strdup(file_relpath);
		if (S_ISDIR(st.st_mode)) {
			file->dir = TRUE;
			test_storage_files_read_dir(home, file_relpath);
			continue;
		}
		int fd = open(path, O_RDONLY);
		if (fd == -1)
			i_fatal("open(%s) failed: %m", path);
		file->size = st.st_size;
		file->data = i_malloc(file->size + 1);
		if (file->size > 0 &&
		    pread_full(fd, file->data, file->size, 0) <= 0)
			i_fatal("pread(%s) failed: %m", path);
		i_close_fd(&fd);
	}
	if (closedir(dirp) < 0)
		i_fatal("closedir(%s) failed: %m", dir);
}

static void test_storage_files_free(void)
{
	struct test_storage_file *file;

	array_foreach_modifiable(&test_files, file) {
		i_free(file->path);
		i_free(file->data);
	}
	array_free(&test_files);
}

/* Restore the home directory, with the given file replaced by data. */
static void
test_storage_files_write(const char *home,
			 const struct test_storage_file *corrupted_file,
			 const unsigned char *data, size_t size)
{
	const struct test_storage_file *file;
	const char *error;

	(void)unlink_directory(home, UNLINK_DIRECTORY_FLAG_RMDIR, &error);
	if (mkdir(home, 0700) < 0)
		i_fatal("mkdir(%s) failed: %m", home);

	/* directories are always before their contents */
	array_foreach(&test_files, file) {
		const char *path = t_strdup_printf("%s/%s", home, file->path);
		if (file->dir) {
			if (mkdir(path, 0700) < 0)
				i_fatal("mkdir(%s) failed: %m", path);
			continue;
		}
		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd == -1)
			i_fatal("open(%s) failed: %m", path);
		if (file == corrupted_file) {
			if (write_full(fd, data, size) < 0)
				i_fatal("write(%s) failed: %m", path);
		} else {
			if (write_full(fd, file->data, file->size) < 0)
				i_fatal("write(%s) failed: %m", path);
		}
		i_close_fd(&fd);
	}
}

static void
test_storage_corrupted_access(const unsigned char *data, size_t size,
			      struct test_storage_corruption_ctx *ctx)
{
	struct test_mail_storage_settings set = *ctx->set;

	set.keep_home = TRUE;
	test_storage_files_write(ctx->home, ctx->file, data, size);
	test_mail_storage_init_user(ctx->storage_ctx, &set);
	T_BEGIN {
		/* Access twice, since the first access may fix the
		   corruption */
		test_storage_access(ctx->storage_ctx->user, TRUE);
		test_storage_access(ctx->storage_ctx->user, TRUE);
	} T_END;
	test_mail_storage_deinit_user(ctx->storage_ctx);
}

/* Names containing '/' match the path relative to home. Other names match
   the filename in any directory. */
static bool
test_storage_file_match(const char *const *fnames, const char *path)
{
	const char *fname = strrchr(path, '/');

	fname = fname == NULL ? path : fname + 1;
	for (; *fnames != NULL; fnames++) {
		if (strcmp(strchr(*fnames, '/') != NULL ? path : fname,
			   *fnames) == 0)
			return TRUE;
	}
	return FALSE;
}

static void
test_storage_corruption(const char *test_name,
			const struct test_mail_storage_settings *set,
			const char *const *fnames)
{
	struct test_storage_corruption_ctx ctx;
	const struct test_storage_file *file;
	failure_callback_t *fatal_callback, *info_callback, *debug_callback;
	unsigned int corrupted_count = 0;

	/* fsyncing would only make the test slower */
	struct test_mail_storage_settings fsync_set = *set;
	ARRAY_TYPE(const_string) extra_input;
	const char *fsync_never = "mail_fsync=never";

	t_array_init(&extra_input, 4);
	if (set->extra_input != NULL) {
		array_append(&extra_input, set->extra_input,
			     str_array_length(set->extra_input));
	}
	array_push_back(&extra_input, &fsync_never);
	array_append_zero(&extra_input);
	fsync_set.extra_input = array_front(&extra_input);
	set = &fsync_set;

	test_begin(test_name);
	i_zero(&ctx);
	ctx.storage_ctx = test_mail_storage_init();
	ctx.set = set;
	ctx.home = t_strconcat(ctx.storage_ctx->home_root, TEST_USERNAME, NULL);

	test_storage_create(ctx.storage_ctx, set);
	for (unsigned int i = 0; fnames[i] != NULL; i++) {
		if (str_ends_with(fnames[i], ".index"))
			test_storage_index_write(ctx.home, fnames[i]);
	}
	i_array_init(&test_files, 64);
	test_storage_files_read_dir(ctx.home, "");

	/* The original must be accessible without errors */
	test_storage_corrupted_access(NULL, 0, &ctx);

	i_get_failure_handlers(&fatal_callback, &orig_error_callback,
			       &info_callback, &debug_callback);
	i_set_error_handler(test_ignore_errors_handler);
	array_foreach(&test_files, file) {
		if (file->dir || !test_storage_file_match(fnames, file->path))
			continue;

		const struct test_corruption_settings corruption_set = {
			.name = t_strdup_printf("%s %s", test_name, file->path),
			.random_count = TEST_RANDOM_COUNT,
			.max_deterministic_count = TEST_MAX_DETERMINISTIC_COUNT,
		};
		ctx.file = file;
		test_corruption_run(&corruption_set, file->data, file->size,
				    test_storage_corrupted_access, &ctx);
		corrupted_count++;
	}
	i_set_error_handler(orig_error_callback);
	/* there may be multiple files with the same name */
	test_assert(corrupted_count >= str_array_length(fnames));

	test_storage_files_free();
	test_mail_storage_deinit(&ctx.storage_ctx);
	test_end();
}

static void test_mailbox_list_index_corruption(void)
{
	static const char *const fnames[] = {
		"dovecot.list.index", "dovecot.list.index.log", NULL
	};
	const struct test_mail_storage_settings set = {
		.username = TEST_USERNAME,
		.driver = "sdbox",
		.hierarchy_sep = "/",
	};
	test_storage_corruption("mailbox list index corruption",
				&set, fnames);
}

static void test_mailbox_list_index_layout_index_corruption(void)
{
	static const char *const fnames[] = {
		"dovecot.list.index", "dovecot.list.index.log", NULL
	};
	static const char *const extra_input[] = {
		"mailbox_list_layout=index",
		NULL
	};
	const struct test_mail_storage_settings set = {
		.username = TEST_USERNAME,
		.driver = "sdbox",
		.hierarchy_sep = "/",
		.extra_input = extra_input,
	};
	test_storage_corruption(
		"mailbox list index corruption (mailbox_list_layout=index)",
		&set, fnames);
}

static void test_mdbox_map_index_corruption(void)
{
	static const char *const fnames[] = {
		"dovecot.map.index", "dovecot.map.index.log", NULL
	};
	const struct test_mail_storage_settings set = {
		.username = TEST_USERNAME,
		.driver = "mdbox",
		.hierarchy_sep = "/",
	};
	test_storage_corruption("mdbox map index corruption", &set, fnames);
}

static void test_thread_index_corruption(void)
{
	static const char *const fnames[] = {
		"mailboxes/INBOX/dbox-Mails/dovecot.index.thread", NULL
	};
	const struct test_mail_storage_settings set = {
		.username = TEST_USERNAME,
		.driver = "sdbox",
		.hierarchy_sep = "/",
	};
	test_storage_corruption("thread index corruption", &set, fnames);
}

int main(int argc, char **argv)
{
	int ret;
	void (*const tests[])(void) = {
		test_mailbox_list_index_corruption,
		test_mailbox_list_index_layout_index_corruption,
		test_mdbox_map_index_corruption,
		test_thread_index_corruption,
		NULL
	};

	master_service = master_service_init("test-mail-storage-corruption",
					     MASTER_SERVICE_FLAG_STANDALONE |
					     MASTER_SERVICE_FLAG_DONT_SEND_STATS |
					     MASTER_SERVICE_FLAG_CONFIG_BUILTIN |
					     MASTER_SERVICE_FLAG_NO_SSL_INIT |
					     MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME,
					     &argc, &argv, "");
	test_dir_init("test-mail-storage-corruption");
	ret = test_run(tests);

	master_service_deinit(&master_service);
	return ret;
}
