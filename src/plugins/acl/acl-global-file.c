/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "strescape.h"
#include "wildcard-match.h"
#include "acl-api-private.h"
#include "acl-global-file.h"

#include <sys/stat.h>

struct acl_global_rights {
	const char *vpattern;
	ARRAY_TYPE(acl_rights) rights;
};

struct acl_global_parse_rights {
	const char *vpattern;
	struct acl_rights rights;
};

struct acl_global_file {
	char *path;
	struct stat prev_st;
	time_t last_refresh_time;

	pool_t rights_pool;
	ARRAY(struct acl_global_rights) rights;

	unsigned int refresh_interval_secs;
	bool debug;
};

struct acl_global_file *
acl_global_file_init(const char *path, unsigned int refresh_interval_secs,
		     bool debug)
{
	struct acl_global_file *file;

	file = i_new(struct acl_global_file, 1);
	file->path = i_strdup(path);
	file->refresh_interval_secs = refresh_interval_secs;
	file->debug = debug;
	i_array_init(&file->rights, 32);
	file->rights_pool = pool_alloconly_create("acl global file rights", 1024);
	return file;
}

void acl_global_file_deinit(struct acl_global_file **_file)
{
	struct acl_global_file *file = *_file;

	*_file = NULL;

	array_free(&file->rights);
	pool_unref(&file->rights_pool);
	i_free(file->path);
	i_free(file);
}

static int acl_global_parse_rights_cmp(const struct acl_global_parse_rights *r1,
				       const struct acl_global_parse_rights *r2)
{
	return strcmp(r1->vpattern, r2->vpattern);
}

struct acl_global_file_parse_ctx {
	struct acl_global_file *file;
	ARRAY(struct acl_global_parse_rights) parse_rights;
};

static int
acl_global_file_parse_line(struct acl_global_file_parse_ctx *ctx,
			   const char *line, const char **error_r)
{
	struct acl_global_parse_rights *pright;
	const char *p, *vpattern;

	if (*line == '"') {
		line++;
		if (str_unescape_next(&line, &vpattern) < 0) {
			*error_r = "Missing '\"'";
			return -1;
		}
		if (line[0] != ' ') {
			*error_r = "Expecting space after '\"'";
			return -1;
		}
		line++;
	} else {
		p = strchr(line, ' ');
		if (p == NULL) {
			*error_r = "Missing ACL rights";
			return -1;
		}
		if (p == line) {
			*error_r = "Empty ACL pattern";
			return -1;
		}
		vpattern = t_strdup_until(line, p);
		line = p + 1;
	}

	pright = array_append_space(&ctx->parse_rights);
	pright->vpattern = p_strdup(ctx->file->rights_pool, vpattern);
	if (acl_rights_parse_line(line, ctx->file->rights_pool,
				  &pright->rights, error_r) < 0)
		return -1;
	pright->rights.global = TRUE;
	return 0;
}

static int acl_global_file_read(struct acl_global_file *file)
{
	struct acl_global_file_parse_ctx ctx;
	struct acl_global_parse_rights *pright;
	struct acl_global_rights *right;
	struct istream *input;
	const char *line, *error, *prev_vpattern;
	unsigned int linenum = 0;
	int ret = 0;

	array_clear(&file->rights);
	p_clear(file->rights_pool);

	i_zero(&ctx);
	ctx.file = file;
	i_array_init(&ctx.parse_rights, 32);

	input = i_stream_create_file(file->path, (size_t)-1);
	i_stream_set_return_partial_line(input, TRUE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		linenum++;
		if (line[0] == '\0' || line[0] == '#')
			continue;
		T_BEGIN {
			ret = acl_global_file_parse_line(&ctx, line, &error);
			if (ret < 0) {
				i_error("Global ACL file %s line %u: %s",
					file->path, linenum, error);
			}
		} T_END;
		if (ret < 0)
			break;
	}
	if (ret == 0 && input->stream_errno != 0) {
		i_error("Couldn't read global ACL file %s: %s",
			file->path, i_stream_get_error(input));
		ret = -1;
	}
	if (ret == 0) {
		const struct stat *st;

		if (i_stream_stat(input, TRUE, &st) < 0) {
			i_error("Couldn't stat global ACL file %s: %s",
				file->path, i_stream_get_error(input));
			ret = -1;
		} else {
			file->prev_st = *st;
		}
	}
	i_stream_destroy(&input);

	/* sort all parsed rights */
	array_sort(&ctx.parse_rights, acl_global_parse_rights_cmp);
	/* combine identical patterns into same structs */
	prev_vpattern = ""; right = NULL;
	array_foreach_modifiable(&ctx.parse_rights, pright) {
		if (right == NULL ||
		    strcmp(prev_vpattern, pright->vpattern) != 0) {
			right = array_append_space(&file->rights);
			right->vpattern = pright->vpattern;
			p_array_init(&right->rights, file->rights_pool, 4);
		}
		array_push_back(&right->rights, &pright->rights);
	}

	array_free(&ctx.parse_rights);
	return ret;
}

int acl_global_file_refresh(struct acl_global_file *file)
{
	struct stat st;

	if (file->last_refresh_time + (time_t)file->refresh_interval_secs > ioloop_time)
		return 0;
	if (file->last_refresh_time != 0) {
		if (stat(file->path, &st) < 0) {
			i_error("stat(%s) failed: %m", file->path);
			return -1;
		}
		if (st.st_ino == file->prev_st.st_ino &&
		    st.st_size == file->prev_st.st_size &&
		    CMP_ST_MTIME(&st, &file->prev_st)) {
			/* no change to the file */
			file->last_refresh_time = ioloop_time;
			return 0;
		}
	}
	if (acl_global_file_read(file) < 0)
		return -1;
	file->last_refresh_time = ioloop_time;
	return 0;
}

void acl_global_file_last_stat(struct acl_global_file *file, struct stat *st_r)
{
	*st_r = file->prev_st;
}

void acl_global_file_get(struct acl_global_file *file, const char *vname,
			 pool_t pool, ARRAY_TYPE(acl_rights) *rights_r)
{
	struct acl_global_rights *global_rights;
	const struct acl_rights *rights;
	struct acl_rights *new_rights;

	array_foreach_modifiable(&file->rights, global_rights) {
		if (!wildcard_match(vname, global_rights->vpattern))
			continue;
		if (file->debug) {
			i_debug("Mailbox '%s' matches global ACL pattern '%s'",
				vname, global_rights->vpattern);
		}
		array_foreach(&global_rights->rights, rights) {
			new_rights = array_append_space(rights_r);
			acl_rights_dup(rights, pool, new_rights);
		}
	}
}

bool acl_global_file_have_any(struct acl_global_file *file, const char *vname)
{
	struct acl_global_rights *rights;

	i_assert(file->last_refresh_time != 0);

	array_foreach_modifiable(&file->rights, rights) {
		if (wildcard_match(vname, rights->vpattern))
			return TRUE;
	}
	return FALSE;
}
