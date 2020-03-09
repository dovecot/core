/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "net.h"
#include "istream.h"
#include "write-full.h"
#include "module-context.h"
#include "rfc822-parser.h"
#include "rfc2231-parser.h"
#include "message-parser.h"
#include "mail-user.h"
#include "fts-parser.h"

#define SCRIPT_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_parser_script_user_module)

#define SCRIPT_HANDSHAKE "VERSION\tscript\t4\t0\nalarm=10\nnoreply\n"

struct content {
	const char *content_type;
	const char *const *extensions;
};

struct fts_parser_script_user {
	union mail_user_module_context module_ctx;

	ARRAY(struct content) content;
};

struct script_fts_parser {
	struct fts_parser parser;

	int fd;
	char *path;

	unsigned char outbuf[IO_BLOCK_SIZE];
	bool failed;
	bool shutdown;
};

static MODULE_CONTEXT_DEFINE_INIT(fts_parser_script_user_module,
				  &mail_user_module_register);

static int script_connect(struct mail_user *user, const char **path_r)
{
	const char *path;
	int fd;

	path = mail_user_plugin_getenv(user, "fts_decoder");
	if (path == NULL)
		return -1;

	if (*path != '/')
		path = t_strconcat(user->set->base_dir, "/", path, NULL);
	fd = net_connect_unix_with_retries(path, 1000);
	if (fd == -1)
		i_error("net_connect_unix(%s) failed: %m", path);
	else
		net_set_nonblock(fd, FALSE);
	*path_r = path;
	return fd;
}

static int script_contents_read(struct mail_user *user)
{
	struct fts_parser_script_user *suser = SCRIPT_USER_CONTEXT(user);
	const char *path, *cmd, *line;
	char **args;
	struct istream *input;
	struct content *content;
	bool eof_seen = FALSE;
	int fd, ret = 0;
	i_assert(suser != NULL);

	fd = script_connect(user, &path);
	if (fd == -1)
		return -1;

	cmd = t_strdup_printf(SCRIPT_HANDSHAKE"\n");
	if (write_full(fd, cmd, strlen(cmd)) < 0) {
		i_error("write(%s) failed: %m", path);
		i_close_fd(&fd);
		return -1;
	}
	input = i_stream_create_fd_autoclose(&fd, 1024);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		/* <content-type> <extension> [<extension> ...] */
		args = p_strsplit_spaces(user->pool, line, " ");
		if (args[0] == NULL) {
			eof_seen = TRUE;
			break;
		}
		if (args[0][0] == '\0' || args[1] == NULL) {
			i_error("parser script sent invalid input: %s", line);
			continue;
		}

		content = array_append_space(&suser->content);
		content->content_type = str_lcase(args[0]);
		content->extensions = (const void *)(args+1);
	}
	if (input->stream_errno != 0) {
		i_error("parser script read(%s) failed: %s", path,
			i_stream_get_error(input));
		ret = -1;
	} else if (!eof_seen) {
		if (input->v_offset == 0)
			i_error("parser script didn't send any data");
		else
			i_error("parser script didn't send empty EOF line");
	}
	i_stream_destroy(&input);
	return ret;
}

static bool script_support_content(struct mail_user *user,
				   const char **content_type,
				   const char *filename)
{
	struct fts_parser_script_user *suser = SCRIPT_USER_CONTEXT(user);
	const struct content *content;
	const char *extension;

	if (suser == NULL) {
		suser = p_new(user->pool, struct fts_parser_script_user, 1);
		p_array_init(&suser->content, user->pool, 32);
		MODULE_CONTEXT_SET(user, fts_parser_script_user_module, suser);
	}
	if (array_count(&suser->content) == 0) {
		if (script_contents_read(user) < 0)
			return FALSE;
	}

	if (strcmp(*content_type, "application/octet-stream") == 0) {
		if (filename == NULL)
			return FALSE;
		extension = strrchr(filename, '.');
		if (extension == NULL)
			return FALSE;
		extension = filename + 1;

		array_foreach(&suser->content, content) {
			if (content->extensions != NULL &&
			    str_array_icase_find(content->extensions, extension)) {
				*content_type = content->content_type;
				return TRUE;
			}
		}
	} else {
		array_foreach(&suser->content, content) {
			if (strcmp(content->content_type, *content_type) == 0)
				return TRUE;
		}
	}
	return FALSE;
}

static void parse_content_disposition(const char *content_disposition,
				      const char **filename_r)
{
	struct rfc822_parser_context parser;
	const char *const *results, *filename2;
	string_t *str;

	*filename_r = NULL;

	if (content_disposition == NULL)
		return;

	rfc822_parser_init(&parser, (const unsigned char *)content_disposition,
			   strlen(content_disposition), NULL);
	rfc822_skip_lwsp(&parser);

	/* type; param; param; .. */
	str = t_str_new(32);
	if (rfc822_parse_mime_token(&parser, str) < 0) {
		rfc822_parser_deinit(&parser);
		return;
	}

	rfc2231_parse(&parser, &results);
	filename2 = NULL;
	for (; *results != NULL; results += 2) {
		if (strcasecmp(results[0], "filename") == 0) {
			*filename_r = results[1];
			break;
		}
		if (strcasecmp(results[0], "filename*") == 0)
			filename2 = results[1];
	}
	if (*filename_r == NULL) {
		/* RFC 2231 style non-ascii filename. we don't really care
		   much about the filename actually, just about its extension */
		*filename_r = filename2;
	}
	rfc822_parser_deinit(&parser);
}

static struct fts_parser *
fts_parser_script_try_init(struct fts_parser_context *parser_context)
{
	struct script_fts_parser *parser;
	const char *filename, *path, *cmd;
	int fd;

	parse_content_disposition(parser_context->content_disposition, &filename);
	if (!script_support_content(parser_context->user, &parser_context->content_type, filename))
		return NULL;

	fd = script_connect(parser_context->user, &path);
	if (fd == -1)
		return NULL;
	cmd = t_strdup_printf(SCRIPT_HANDSHAKE"%s\n\n", parser_context->content_type);
	if (write_full(fd, cmd, strlen(cmd)) < 0) {
		i_error("write(%s) failed: %m", path);
		i_close_fd(&fd);
		return NULL;
	}

	parser = i_new(struct script_fts_parser, 1);
	parser->parser.v = fts_parser_script;
	parser->path = i_strdup(path);
	parser->fd = fd;
	return &parser->parser;
}

static void fts_parser_script_more(struct fts_parser *_parser,
				   struct message_block *block)
{
	struct script_fts_parser *parser = (struct script_fts_parser *)_parser;
	ssize_t ret;

	if (block->size > 0) {
		/* first we'll send everything to the script */
		if (!parser->failed &&
		    write_full(parser->fd, block->data, block->size) < 0) {
			i_error("write(%s) failed: %m", parser->path);
			parser->failed = TRUE;
		}
		block->size = 0;
	} else {
		if (!parser->shutdown) {
			if (shutdown(parser->fd, SHUT_WR) < 0)
				i_error("shutdown(%s) failed: %m", parser->path);
			parser->shutdown = TRUE;
		}
		/* read the result from the script */
		ret = read(parser->fd, parser->outbuf, sizeof(parser->outbuf));
		if (ret < 0)
			i_error("read(%s) failed: %m", parser->path);
		else {
			block->data = parser->outbuf;
			block->size = ret;
		}
	}
}

static int fts_parser_script_deinit(struct fts_parser *_parser,
				    const char **retriable_err_msg_r ATTR_UNUSED)
{
	struct script_fts_parser *parser = (struct script_fts_parser *)_parser;
	int ret = parser->failed ? -1 : 1;

	if (close(parser->fd) < 0)
		i_error("close(%s) failed: %m", parser->path);
	i_free(parser->path);
	i_free(parser);
	return ret;
}

struct fts_parser_vfuncs fts_parser_script = {
	fts_parser_script_try_init,
	fts_parser_script_more,
	fts_parser_script_deinit,
	NULL
};
