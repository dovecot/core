/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "crc32.h"
#include "istream.h"
#include "str.h"
#include "imap-parser.h"
#include "imap-match.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "mail-search-parser.h"
#include "virtual-storage.h"
#include "virtual-plugin.h"

#include <unistd.h>
#include <fcntl.h>

struct virtual_parse_context {
	struct virtual_mailbox *mbox;
	struct istream *input;

	pool_t pool;
	string_t *rule;
	unsigned int rule_idx;

	char sep;
	bool have_wildcards;
};

static struct mail_search_args *
virtual_search_args_parse(const string_t *rule, const char **error_r)
{
	struct istream *input;
	struct imap_parser *imap_parser;
	const struct imap_arg *args;
	struct mail_search_parser *parser;
	struct mail_search_args *sargs;
	bool fatal;
	int ret;

	if (str_len(rule) == 0) {
		sargs = mail_search_build_init();
		mail_search_build_add_all(sargs);
		return sargs;
	}

	input = i_stream_create_from_data(str_data(rule), str_len(rule));
	(void)i_stream_read(input);

	imap_parser = imap_parser_create(input, NULL, (size_t)-1);
	ret = imap_parser_finish_line(imap_parser, 0,  0, &args);
	if (ret < 0) {
		sargs = NULL;
		*error_r = t_strdup(imap_parser_get_error(imap_parser, &fatal));
	} else {
		parser = mail_search_parser_init_imap(args);
		if (mail_search_build(mail_search_register_get_imap(),
				      parser, "UTF-8", &sargs, error_r) < 0)
			sargs = NULL;
		mail_search_parser_deinit(&parser);
	}

	imap_parser_destroy(&imap_parser);
	i_stream_destroy(&input);
	return sargs;
}

static int
virtual_config_add_rule(struct virtual_parse_context *ctx, const char **error_r)
{
	struct virtual_backend_box *const *bboxes;
	struct mail_search_args *search_args;
	unsigned int i, count;

	if (ctx->rule_idx == array_count(&ctx->mbox->backend_boxes)) {
		i_assert(str_len(ctx->rule) == 0);
		return 0;
	}

	ctx->mbox->search_args_crc32 =
		crc32_str_more(ctx->mbox->search_args_crc32, str_c(ctx->rule));
	search_args = virtual_search_args_parse(ctx->rule, error_r);
	str_truncate(ctx->rule, 0);
	if (search_args == NULL) {
		*error_r = t_strconcat("Previous search rule is invalid: ",
				       *error_r, NULL);
		return -1;
	}

	/* update at all the mailboxes that were introduced since the previous
	   rule. */
	bboxes = array_get(&ctx->mbox->backend_boxes, &count);
	i_assert(ctx->rule_idx < count);
	for (i = ctx->rule_idx; i < count; i++) {
		i_assert(bboxes[i]->search_args == NULL);
		mail_search_args_ref(search_args);
		bboxes[i]->search_args = search_args;
	}
	mail_search_args_unref(&search_args);

	ctx->rule_idx = array_count(&ctx->mbox->backend_boxes);
	return 0;
}

static int
virtual_config_parse_line(struct virtual_parse_context *ctx, const char *line,
			  const char **error_r)
{
	struct mail_user *user = ctx->mbox->storage->storage.user;
	struct virtual_backend_box *bbox;
	const char *name;

	if (*line == ' ' || *line == '\t') {
		/* continues the previous search rule */
		if (ctx->rule_idx == array_count(&ctx->mbox->backend_boxes)) {
			*error_r = "Search rule without a mailbox";
			return -1;
		}
		while (*line == ' ' || *line == '\t') line++;
		str_append_c(ctx->rule, ' ');
		str_append(ctx->rule, line);
		return 0;
	}
	/* if there is no rule yet, it means we want the previous mailboxes
	   to use the rule that comes later */
	if (str_len(ctx->rule) > 0) {
		if (virtual_config_add_rule(ctx, error_r) < 0)
			return -1;
	}

	/* new mailbox. the search args are added to it later. */
	bbox = p_new(ctx->pool, struct virtual_backend_box, 1);
	if (strcasecmp(line, "INBOX") == 0)
		line = "INBOX";
	bbox->name = p_strdup(ctx->pool, line);
	if (*line == '-' || *line == '+' || *line == '!') line++;
	bbox->ns = strcasecmp(line, "INBOX") == 0 ?
		mail_namespace_find_inbox(user->namespaces) :
		mail_namespace_find(user->namespaces, &line);
	if (bbox->ns == NULL) {
		*error_r = t_strdup_printf("Namespace not found for %s",
					   bbox->name);
		return -1;
	}
	if (bbox->name[0] == '+') {
		bbox->name++;
		bbox->clear_recent = TRUE;
	}

	if (strchr(bbox->name, '*') != NULL ||
	    strchr(bbox->name, '%') != NULL) {
		name = bbox->name[0] == '-' ? bbox->name + 1 : bbox->name;
		bbox->glob = imap_match_init(ctx->pool, name, TRUE, ctx->sep);
		ctx->have_wildcards = TRUE;
	} else if (bbox->name[0] == '!') {
		/* save messages here */
		if (ctx->mbox->save_bbox != NULL) {
			*error_r = "Multiple save mailboxes defined";
			return -1;
		}
		bbox->name++;
		ctx->mbox->save_bbox = bbox;
	}
	array_append(&ctx->mbox->backend_boxes, &bbox, 1);
	return 0;
}

static void
virtual_mailbox_get_list_patterns(struct virtual_parse_context *ctx)
{
	struct virtual_mailbox *mbox = ctx->mbox;
	ARRAY_TYPE(mailbox_virtual_patterns) *dest;
	struct mailbox_virtual_pattern pattern;
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;

	memset(&pattern, 0, sizeof(pattern));
	bboxes = array_get_modifiable(&mbox->backend_boxes, &count);
	p_array_init(&mbox->list_include_patterns, ctx->pool, count);
	p_array_init(&mbox->list_exclude_patterns, ctx->pool, count);
	for (i = 0; i < count; i++) {
		pattern.ns = bboxes[i]->ns;
		pattern.pattern = bboxes[i]->name;
		if (*pattern.pattern != '-')
			dest = &mbox->list_include_patterns;
		else {
			dest = &mbox->list_exclude_patterns;
			pattern.pattern++;
		}
		array_append(dest, &pattern, 1);
	}
}

static void
separate_wildcard_mailboxes(struct virtual_mailbox *mbox,
			    ARRAY_TYPE(virtual_backend_box) *wildcard_boxes,
			    ARRAY_TYPE(virtual_backend_box) *neg_boxes)
{
	struct virtual_backend_box *const *bboxes;
	ARRAY_TYPE(virtual_backend_box) *dest;
	unsigned int i, count;

	bboxes = array_get_modifiable(&mbox->backend_boxes, &count);
	t_array_init(wildcard_boxes, I_MIN(16, count));
	t_array_init(neg_boxes, 4);
	for (i = 0; i < count;) {
		if (*bboxes[i]->name == '-')
			dest = neg_boxes;
		else if (bboxes[i]->glob != NULL)
			dest = wildcard_boxes;
		else {
			dest = NULL;
			i++;
		}

		if (dest != NULL) {
			array_append(dest, &bboxes[i], 1);
			array_delete(&mbox->backend_boxes, i, 1);
			bboxes = array_get_modifiable(&mbox->backend_boxes,
						      &count);
		}
	}
}

static void virtual_config_copy_expanded(struct virtual_parse_context *ctx,
					 struct virtual_backend_box *wbox,
					 const char *name)
{
	struct virtual_backend_box *bbox;

	bbox = p_new(ctx->pool, struct virtual_backend_box, 1);
	*bbox = *wbox;
	bbox->name = p_strdup(ctx->pool, name);
	bbox->glob = NULL;
	bbox->wildcard = TRUE;
	mail_search_args_ref(bbox->search_args);
	array_append(&ctx->mbox->backend_boxes, &bbox, 1);
}

static bool virtual_config_match(const struct mailbox_info *info,
				 ARRAY_TYPE(virtual_backend_box) *boxes_arr,
				 unsigned int *idx_r)
{
	struct virtual_backend_box *const *boxes;
	unsigned int i, count;

	boxes = array_get_modifiable(boxes_arr, &count);
	for (i = 0; i < count; i++) {
		if (boxes[i]->glob != NULL) {
			/* we match only one namespace for each pattern. */
			if (boxes[i]->ns == info->ns &&
			    imap_match(boxes[i]->glob,
				       info->name) == IMAP_MATCH_YES) {
				*idx_r = i;
				return TRUE;
			}
		} else {
			i_assert(boxes[i]->name[0] == '-');
			if (strcmp(boxes[i]->name + 1, info->name) == 0) {
				*idx_r = i;
				return TRUE;
			}
		}
	}
	return FALSE;
}

static int virtual_config_expand_wildcards(struct virtual_parse_context *ctx)
{
	const enum namespace_type iter_ns_types =
		NAMESPACE_PRIVATE | NAMESPACE_SHARED | NAMESPACE_PUBLIC;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct mail_user *user = ctx->mbox->storage->storage.user;
	ARRAY_TYPE(virtual_backend_box) wildcard_boxes, neg_boxes;
	struct mailbox_list_iterate_context *iter;
	struct virtual_backend_box *const *wboxes;
	const char **patterns;
	const struct mailbox_info *info;
	unsigned int i, j, count;

	separate_wildcard_mailboxes(ctx->mbox, &wildcard_boxes, &neg_boxes);

	/* get patterns we want to list */
	wboxes = array_get_modifiable(&wildcard_boxes, &count);
	if (count == 0) {
		/* only negative wildcards - doesn't really make sense.
		   just ignore. */
		return 0;
	}
	patterns = t_new(const char *, count + 1);
	for (i = 0; i < count; i++)
		patterns[i] = wboxes[i]->name;

	/* match listed mailboxes to wildcards */
	iter = mailbox_list_iter_init_namespaces(user->namespaces, patterns,
						 iter_ns_types, iter_flags);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		/* skip non-selectable mailboxes (especially mbox
		   directories) */
		if ((info->flags & MAILBOX_NOSELECT) != 0)
			continue;

		if (virtual_config_match(info, &wildcard_boxes, &i) &&
		    !virtual_config_match(info, &neg_boxes, &j) &&
		    virtual_backend_box_lookup_name(ctx->mbox,
						    info->name) == NULL) {
			virtual_config_copy_expanded(ctx, wboxes[i],
						     info->name);
		}
	}
	for (i = 0; i < count; i++)
		mail_search_args_unref(&wboxes[i]->search_args);
	return mailbox_list_iter_deinit(&iter);
}

static void virtual_config_search_args_dup(struct virtual_mailbox *mbox)
{
	struct virtual_backend_box *const *bboxes;
	struct mail_search_args *old_args;
	unsigned int i, count;

	bboxes = array_get_modifiable(&mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		old_args = bboxes[i]->search_args;
		bboxes[i]->search_args = mail_search_args_dup(old_args);
		mail_search_args_unref(&old_args);
	}
}

int virtual_config_read(struct virtual_mailbox *mbox)
{
	struct mail_storage *storage = mbox->box.storage;
	struct virtual_parse_context ctx;
	struct stat st;
	const char *path, *line, *error;
	unsigned int linenum = 0;
	int fd, ret = 0;

	i_array_init(&mbox->backend_boxes, 8);
	mbox->search_args_crc32 = (uint32_t)-1;

	path = t_strconcat(mbox->box.path, "/"VIRTUAL_CONFIG_FNAME, NULL);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == EACCES) {
			mail_storage_set_critical(storage, "%s",
				mail_error_eacces_msg("stat", mbox->box.path));
		} else if (errno != ENOENT) {
			mail_storage_set_critical(storage,
						  "open(%s) failed: %m", path);
		} else if (stat(mbox->box.path, &st) == 0) {
			mail_storage_set_error(storage, MAIL_ERROR_NOTPOSSIBLE,
				"Virtual mailbox missing configuration file");
		} else if (errno == ENOENT) {
			mail_storage_set_error(storage, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(mbox->box.name));
		} else {
			mail_storage_set_critical(storage,
				"stat(%s) failed: %m", mbox->box.path);
		}
		return -1;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.sep = mail_namespaces_get_root_sep(storage->user->namespaces);
	ctx.mbox = mbox;
	ctx.pool = mbox->box.pool;
	ctx.rule = t_str_new(256);
	ctx.input = i_stream_create_fd(fd, (size_t)-1, FALSE);
	i_stream_set_return_partial_line(ctx.input, TRUE);
	while ((line = i_stream_read_next_line(ctx.input)) != NULL) {
		linenum++;
		if (*line == '#')
			continue;
		if (*line == '\0')
			ret = virtual_config_add_rule(&ctx, &error);
		else
			ret = virtual_config_parse_line(&ctx, line, &error);
		if (ret < 0) {
			mail_storage_set_critical(storage,
						  "%s: Error at line %u: %s",
						  path, linenum, error);
			break;
		}
	}
	if (ret == 0) {
		ret = virtual_config_add_rule(&ctx, &error);
		if (ret < 0) {
			mail_storage_set_critical(storage,
						  "%s: Error at line %u: %s",
						  path, linenum, error);
		}
	}

	virtual_mailbox_get_list_patterns(&ctx);
	if (ret == 0 && ctx.have_wildcards)
		ret = virtual_config_expand_wildcards(&ctx);

	if (ret == 0 && array_count(&mbox->backend_boxes) == 0) {
		mail_storage_set_critical(storage,
					  "%s: No mailboxes defined", path);
		ret = -1;
	}
	if (ret == 0)
		virtual_config_search_args_dup(mbox);
	i_stream_unref(&ctx.input);
	(void)close(fd);
	return ret;
}

void virtual_config_free(struct virtual_mailbox *mbox)
{
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;

	if (!array_is_created(&mbox->backend_boxes)) {
		/* mailbox wasn't opened */
		return;
	}

	bboxes = array_get_modifiable(&mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (bboxes[i]->search_args != NULL)
			mail_search_args_unref(&bboxes[i]->search_args);
	}
	array_free(&mbox->backend_boxes);
}
