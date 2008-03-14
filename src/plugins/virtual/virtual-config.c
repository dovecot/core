/* Copyright (c) 2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "str.h"
#include "imap-parser.h"
#include "mail-search-build.h"
#include "virtual-storage.h"

#include <unistd.h>
#include <fcntl.h>

struct virtual_parse_context {
	struct virtual_mailbox *mbox;
	struct istream *input;

	pool_t pool;
	string_t *rule;
	unsigned int mailbox_id;
	unsigned int rule_idx;
};

static struct mail_search_arg *
virtual_search_args_parse(pool_t pool, const string_t *rule,
			  const char **error_r)
{
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args;
	struct mail_search_arg *sargs;
	bool fatal;
	int ret;

	input = i_stream_create_from_data(str_data(rule), str_len(rule));
	(void)i_stream_read(input);

	parser = imap_parser_create(input, NULL, (size_t)-1);
	ret = imap_parser_finish_line(parser, 0,  0, &args);
	if (ret < 0) {
		sargs = NULL;
		*error_r = t_strdup(imap_parser_get_error(parser, &fatal));
	} else {
		sargs = mail_search_build_from_imap_args(pool, args, error_r);
	}

	imap_parser_destroy(&parser);
	i_stream_destroy(&input);
	return sargs;
}

static int
virtual_config_add_rule(struct virtual_parse_context *ctx, const char **error_r)
{
	struct virtual_backend_box *const *bboxes;
	struct mail_search_arg *search_args;
	unsigned int i, count;

	if (str_len(ctx->rule) == 0)
		return 0;

	search_args = virtual_search_args_parse(ctx->pool, ctx->rule, error_r);
	str_truncate(ctx->rule, 0);
	if (search_args == NULL) {
		*error_r = t_strconcat("Previous search rule is invalid: ",
				       *error_r, NULL);
		return -1;
	}

	bboxes = array_get(&ctx->mbox->backend_boxes, &count);
	i_assert(ctx->rule_idx < count);
	for (i = ctx->rule_idx; i < count; i++)
		bboxes[i]->search_args = search_args;

	ctx->rule_idx = array_count(&ctx->mbox->backend_boxes);
	return 0;
}

static int
virtual_config_parse_line(struct virtual_parse_context *ctx, const char *line,
			  const char **error_r)
{
	struct virtual_backend_box *bbox;

	if (*line == ' ') {
		/* continues the previous search rule */
		if (ctx->rule_idx == array_count(&ctx->mbox->backend_boxes)) {
			*error_r = "Search rule without a mailbox";
			return -1;
		}
		str_append(ctx->rule, line);
		return 0;
	}
	if (virtual_config_add_rule(ctx, error_r) < 0)
		return -1;

	/* new mailbox */
	bbox = p_new(ctx->pool, struct virtual_backend_box, 1);
	bbox->mailbox_id = ++ctx->mailbox_id;
	bbox->name = p_strdup(ctx->pool, line);
	array_append(&ctx->mbox->backend_boxes, &bbox, 1);
	return 0;
}

int virtual_config_read(struct virtual_mailbox *mbox)
{
	struct virtual_parse_context ctx;
	const char *path, *line, *error;
	unsigned int linenum = 0;
	int fd, ret = 0;

	i_array_init(&mbox->backend_boxes, 8);

	path = t_strconcat(mbox->path, "/"VIRTUAL_CONFIG_FNAME, NULL);
	fd = open(path, O_RDWR);
	if (fd == -1) {
		if (errno == ENOENT) {
			mail_storage_set_error(mbox->ibox.storage,
				MAIL_ERROR_NOTPOSSIBLE,
				"Virtual mailbox missing configuration file");
			return -1;
		}
		mail_storage_set_critical(mbox->ibox.storage,
					  "open(%s) failed: %m", path);
		return -1;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.mbox = mbox;
	ctx.pool = mbox->ibox.box.pool;
	ctx.rule = t_str_new(256);
	ctx.input = i_stream_create_fd(fd, (size_t)-1, FALSE);
	while ((line = i_stream_read_next_line(ctx.input)) != NULL) {
		linenum++;
		if (*line == '#')
			continue;
		if (*line == '\0')
			ret = virtual_config_add_rule(&ctx, &error);
		else
			ret = virtual_config_parse_line(&ctx, line, &error);
		if (ret < 0) {
			mail_storage_set_critical(mbox->ibox.storage,
						  "%s: Error at line %u: %s",
						  path, linenum, error);
			break;
		}
	}
	if (ret == 0)
		ret = virtual_config_add_rule(&ctx, &error);

	if (ret == 0 && array_count(&mbox->backend_boxes) == 0) {
		mail_storage_set_critical(mbox->ibox.storage,
					  "%s: No mailboxes defined", path);
		ret = -1;
	}
	i_stream_unref(&ctx.input);
	(void)close(fd);
	return ret;
}
