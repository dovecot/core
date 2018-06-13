/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "time-util.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>

#define LAST_LOG_TYPE LOG_TYPE_PANIC
#define TEST_LOG_MSG_PREFIX "This is Dovecot's "
#define LOG_ERRORS_FNAME "log-errors"
#define LOG_TIMESTAMP_FORMAT "%b %d %H:%M:%S"

extern struct doveadm_cmd doveadm_cmd_log[];

static void ATTR_NULL(2)
cmd_log_test(int argc ATTR_UNUSED, char *argv[] ATTR_UNUSED)
{
	struct failure_context ctx;
	unsigned int i;

	master_service->log_initialized = FALSE;
	master_service->flags |= MASTER_SERVICE_FLAG_DONT_LOG_TO_STDERR;
	master_service_init_log(master_service, "doveadm: ");

	i_zero(&ctx);
	for (i = 0; i < LAST_LOG_TYPE; i++) {
		const char *prefix = failure_log_type_prefixes[i];

		/* add timestamp so that syslog won't just write
		   "repeated message" text */
		ctx.type = i;
		i_log_type(&ctx, TEST_LOG_MSG_PREFIX"%s log (%u)",
			   t_str_lcase(t_strcut(prefix, ':')),
			   (unsigned int)ioloop_time);
	}
}

static void cmd_log_reopen(int argc ATTR_UNUSED, char *argv[] ATTR_UNUSED)
{
	doveadm_master_send_signal(SIGUSR1);
}

struct log_find_file {
	const char *path;
	uoff_t size;

	/* 1 << enum log_type */
	unsigned int mask;
};

struct log_find_context {
	pool_t pool;
	HASH_TABLE(char *, struct log_find_file *) files;
};

static void cmd_log_find_add(struct log_find_context *ctx,
			     const char *path, enum log_type type)
{
	struct log_find_file *file;
	char *key;

	file = hash_table_lookup(ctx->files, path);
	if (file == NULL) {
		file = p_new(ctx->pool, struct log_find_file, 1);
		file->path = key = p_strdup(ctx->pool, path);
		hash_table_insert(ctx->files, key, file);
	}

	file->mask |= 1 << type;
}

static void
cmd_log_find_syslog_files(struct log_find_context *ctx, const char *path)
{
	struct log_find_file *file;
	DIR *dir;
	struct dirent *d;
	struct stat st;
	char *key;
	string_t *full_path;
	size_t dir_len;

	dir = opendir(path);
	if (dir == NULL) {
		i_error("opendir(%s) failed: %m", path);
		return;
	}

	full_path = t_str_new(256);
	str_append(full_path, path);
	str_append_c(full_path, '/');
	dir_len = str_len(full_path);

	while ((d = readdir(dir)) != NULL) {
		if (d->d_name[0] == '.')
			continue;

		str_truncate(full_path, dir_len);
		str_append(full_path, d->d_name);
		if (stat(str_c(full_path), &st) < 0)
			continue;

		if (S_ISDIR(st.st_mode)) {
			/* recursively go through all subdirectories */
			cmd_log_find_syslog_files(ctx, str_c(full_path));
		} else if (hash_table_lookup(ctx->files,
					     str_c(full_path)) == NULL) {
			file = p_new(ctx->pool, struct log_find_file, 1);
			file->size = st.st_size;
			file->path = key =
				p_strdup(ctx->pool, str_c(full_path));
			hash_table_insert(ctx->files, key, file);
		}
	}

	(void)closedir(dir);
}

static bool log_type_find(const char *str, enum log_type *type_r)
{
	unsigned int i;
	size_t len = strlen(str);

	for (i = 0; i < LAST_LOG_TYPE; i++) {
		if (strncasecmp(str, failure_log_type_prefixes[i], len) == 0 &&
		    failure_log_type_prefixes[i][len] == ':') {
			*type_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

static void cmd_log_find_syslog_file_messages(struct log_find_file *file)
{
	struct istream *input;
	const char *line, *p;
	enum log_type type;
	int fd;

	fd = open(file->path, O_RDONLY);
	if (fd == -1)
		return;
	
	input = i_stream_create_fd_autoclose(&fd, 1024);
	i_stream_seek(input, file->size);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		p = strstr(line, TEST_LOG_MSG_PREFIX);
		if (p == NULL)
			continue;
		p += strlen(TEST_LOG_MSG_PREFIX);

		/* <type> log */
		T_BEGIN {
			if (log_type_find(t_strcut(p, ' '), &type))
				file->mask |= 1 << type;
		} T_END;
	}
	i_stream_destroy(&input);
}

static void cmd_log_find_syslog_messages(struct log_find_context *ctx)
{
	struct hash_iterate_context *iter;
	struct stat st;
	char *key;
	struct log_find_file *file;

	iter = hash_table_iterate_init(ctx->files);
	while (hash_table_iterate(iter, ctx->files, &key, &file)) {
		if (stat(file->path, &st) < 0 ||
		    (uoff_t)st.st_size <= file->size)
			continue;

		cmd_log_find_syslog_file_messages(file);
	}
	hash_table_iterate_deinit(&iter);
}

static void
cmd_log_find_syslog(struct log_find_context *ctx, int argc, char *argv[])
{
	const char *log_dir;
	struct stat st;

	if (argc > 1)
		log_dir = argv[1];
	else if (stat("/var/log", &st) == 0 && S_ISDIR(st.st_mode))
		log_dir = "/var/log";
	else if (stat("/var/adm", &st) == 0 && S_ISDIR(st.st_mode))
		log_dir = "/var/adm";
	else
		return;

	printf("Looking for log files from %s\n", log_dir);
	cmd_log_find_syslog_files(ctx, log_dir);
	cmd_log_test(0, NULL);

	/* give syslog some time to write the messages to files */
	sleep(1);
	cmd_log_find_syslog_messages(ctx);
}

static void cmd_log_find(int argc, char *argv[])
{
	const struct master_service_settings *set;
	const char *log_file_path;
	struct log_find_context ctx;
	unsigned int i;

	i_zero(&ctx);
	ctx.pool = pool_alloconly_create("log file", 1024*32);
	hash_table_create(&ctx.files, ctx.pool, 0, str_hash, strcmp);

	/* first get the paths that we know are used */
	set = master_service_settings_get(master_service);
	log_file_path = set->log_path;
	if (strcmp(log_file_path, "syslog") == 0)
		log_file_path = "";
	if (*log_file_path != '\0') {
		cmd_log_find_add(&ctx, log_file_path, LOG_TYPE_WARNING);
		cmd_log_find_add(&ctx, log_file_path, LOG_TYPE_ERROR);
		cmd_log_find_add(&ctx, log_file_path, LOG_TYPE_FATAL);
	}

	if (strcmp(set->info_log_path, "syslog") != 0) {
		if (*set->info_log_path != '\0')
			log_file_path = set->info_log_path;
		if (*log_file_path != '\0')
			cmd_log_find_add(&ctx, log_file_path, LOG_TYPE_INFO);
	}

	if (strcmp(set->debug_log_path, "syslog") != 0) {
		if (*set->debug_log_path != '\0')
			log_file_path = set->debug_log_path;
		if (*log_file_path != '\0')
			cmd_log_find_add(&ctx, log_file_path, LOG_TYPE_DEBUG);
	}

	if (*set->log_path == '\0' ||
	    strcmp(set->log_path, "syslog") == 0 ||
	    strcmp(set->info_log_path, "syslog") == 0 ||
	    strcmp(set->debug_log_path, "syslog") == 0) {
		/* at least some logs were logged via syslog */
		cmd_log_find_syslog(&ctx, argc, argv);
	}

	/* print them */
	for (i = 0; i < LAST_LOG_TYPE; i++) {
		struct hash_iterate_context *iter;
		char *key;
		struct log_find_file *file;
		bool found = FALSE;

		iter = hash_table_iterate_init(ctx.files);
		while (hash_table_iterate(iter, ctx.files, &key, &file)) {
			if ((file->mask & (1 << i)) != 0) {
				printf("%s%s\n", failure_log_type_prefixes[i],
				       file->path);
				found = TRUE;
			}
		}
		hash_table_iterate_deinit(&iter);

		if (!found)
			printf("%sNot found\n", failure_log_type_prefixes[i]);
	}
	hash_table_destroy(&ctx.files);
	pool_unref(&ctx.pool);
}

static const char *t_cmd_log_error_trim(const char *orig)
{
	size_t pos;

	/* Trim whitespace from suffix and remove ':' if it exists */
	for (pos = strlen(orig); pos > 0; pos--) {
		if (orig[pos-1] != ' ') {
			if (orig[pos-1] == ':') 
				pos--;
			break;
		}
	}
	return orig[pos] == '\0' ? orig : t_strndup(orig, pos);
}

static void cmd_log_error_write(const char *const *args, time_t min_timestamp)
{
	/* <type> <timestamp> <prefix> <text> */
	const char *type_prefix = "?";
	unsigned int type;
	time_t t;

	/* find type's prefix */
	for (type = 0; type < LOG_TYPE_COUNT; type++) {
		if (strcmp(args[0], failure_log_type_names[type]) == 0) {
			type_prefix = failure_log_type_prefixes[type];
			break;
		}
	}

	if (str_to_time(args[1], &t) < 0) {
		i_error("Invalid timestamp: %s", args[1]);
		t = 0;
	}
	if (t >= min_timestamp) {
		doveadm_print(t_strflocaltime(LOG_TIMESTAMP_FORMAT, t));
		doveadm_print(t_cmd_log_error_trim(args[2]));
		doveadm_print(t_cmd_log_error_trim(type_prefix));
		doveadm_print(args[3]);
	}
}

static void cmd_log_errors(int argc, char *argv[])
{
	struct istream *input;
	const char *path, *line, *const *args;
	time_t min_timestamp = 0;
	int c, fd;

	while ((c = getopt(argc, argv, "s:")) > 0) {
		switch (c) {
		case 's':
			if (str_to_time(optarg, &min_timestamp) < 0)
				i_fatal("Invalid timestamp: %s", optarg);
			break;
		default:
			help(&doveadm_cmd_log[3]);
		}
	}
	argv += optind - 1;
	if (argv[1] != NULL)
		help(&doveadm_cmd_log[3]);

	path = t_strconcat(doveadm_settings->base_dir,
			   "/"LOG_ERRORS_FNAME, NULL);
	fd = net_connect_unix(path);
	if (fd == -1)
		i_fatal("net_connect_unix(%s) failed: %m", path);
	net_set_nonblock(fd, FALSE);

	input = i_stream_create_fd_autoclose(&fd, (size_t)-1);

	doveadm_print_init(DOVEADM_PRINT_TYPE_FORMATTED);
	doveadm_print_formatted_set_format("%{timestamp} %{type}: %{prefix}: %{text}\n");

	doveadm_print_header_simple("timestamp");
	doveadm_print_header_simple("prefix");
	doveadm_print_header_simple("type");
	doveadm_print_header_simple("text");

	while ((line = i_stream_read_next_line(input)) != NULL) T_BEGIN {
		args = t_strsplit_tabescaped(line);
		if (str_array_length(args) == 4)
			cmd_log_error_write(args, min_timestamp);
		else {
			i_error("Invalid input from log: %s", line);
			doveadm_exit_code = EX_PROTOCOL;
		}
	} T_END;
	i_stream_destroy(&input);
}

struct doveadm_cmd doveadm_cmd_log[] = {
	{ cmd_log_test, "log test", "" },
	{ cmd_log_reopen, "log reopen", "" },
	{ cmd_log_find, "log find", "[<dir>]" },
};

struct doveadm_cmd_ver2 doveadm_cmd_log_errors_ver2 = {
	.name = "log errors",
	.usage = "[-s <min_timestamp>]",
	.old_cmd = cmd_log_errors,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('s', "since", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAMS_END
};

void doveadm_register_log_commands(void)
{
	unsigned int i;

	doveadm_cmd_register_ver2(&doveadm_cmd_log_errors_ver2);

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_log); i++)
		doveadm_register_cmd(&doveadm_cmd_log[i]);
}
