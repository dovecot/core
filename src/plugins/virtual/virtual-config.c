/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "crc32.h"
#include "istream.h"
#include "str.h"
#include "unichar.h"
#include "wildcard-match.h"
#include "imap-parser.h"
#include "imap-match.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "mail-search-parser.h"
#include "mailbox-attribute.h"
#include "mailbox-list-iter.h"
#include "imap-metadata.h"
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
	bool have_mailbox_defines;
};

static struct mail_search_args *
virtual_search_args_parse(const string_t *rule, const char **error_r)
{
	struct istream *input;
	struct imap_parser *imap_parser;
	const struct imap_arg *args;
	struct mail_search_parser *parser;
	struct mail_search_args *sargs;
	const char *charset = "UTF-8";
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
		*error_r = t_strdup(imap_parser_get_error(imap_parser, NULL));
	} else {
		parser = mail_search_parser_init_imap(args);
		if (mail_search_build(mail_search_register_get_imap(),
				      parser, &charset, &sargs, error_r) < 0)
			sargs = NULL;
		mail_search_parser_deinit(&parser);
	}

	imap_parser_unref(&imap_parser);
	i_stream_destroy(&input);
	return sargs;
}

static int
virtual_config_add_rule(struct virtual_parse_context *ctx, const char **error_r)
{
	struct virtual_backend_box *const *bboxes;
	struct mail_search_args *search_args;
	unsigned int i, count;

	*error_r = NULL;

	if (ctx->rule_idx == array_count(&ctx->mbox->backend_boxes)) {
		i_assert(str_len(ctx->rule) == 0);
		return 0;
	}

	ctx->mbox->search_args_crc32 =
		crc32_str_more(ctx->mbox->search_args_crc32, str_c(ctx->rule));
	search_args = virtual_search_args_parse(ctx->rule, error_r);
	str_truncate(ctx->rule, 0);
	if (search_args == NULL) {
		i_assert(*error_r != NULL);
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
	const char *p;
	bool no_wildcards = FALSE;

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
	if (!uni_utf8_str_is_valid(line)) {
		*error_r = t_strdup_printf("Mailbox name not UTF-8: %s",
					   line);
		return -1;
	}

	/* new mailbox. the search args are added to it later. */
	bbox = p_new(ctx->pool, struct virtual_backend_box, 1);
	bbox->virtual_mbox = ctx->mbox;
	if (strcasecmp(line, "INBOX") == 0)
		line = "INBOX";
	bbox->name = p_strdup(ctx->pool, line);
	switch (bbox->name[0]) {
	case '+':
		bbox->name++;
		bbox->clear_recent = TRUE;
		break;
	case '-':
		bbox->name++;
		bbox->negative_match = TRUE;
		break;
	case '!':
		/* save messages here */
		if (ctx->mbox->save_bbox != NULL) {
			*error_r = "Multiple save mailboxes defined";
			return -1;
		}
		bbox->name++;
		ctx->mbox->save_bbox = bbox;
		no_wildcards = TRUE;
		break;
	}
	if (bbox->name[0] == '/') {
		/* [+-!]/metadata entry:value */
		if ((p = strchr(bbox->name, ':')) == NULL) {
			*error_r = "':' separator missing between metadata entry name and value";
			return -1;
		}
		bbox->metadata_entry = p_strdup_until(ctx->pool, bbox->name, p++);
		bbox->metadata_value = p;
		if (!imap_metadata_verify_entry_name(bbox->metadata_entry, error_r))
			return -1;
		no_wildcards = TRUE;
	}

	if (!no_wildcards &&
	    (strchr(bbox->name, '*') != NULL ||
	     strchr(bbox->name, '%') != NULL)) {
		bbox->glob = imap_match_init(ctx->pool, bbox->name, TRUE, ctx->sep);
		ctx->have_wildcards = TRUE;
	}
	if (bbox->metadata_entry == NULL) {
		/* now that the prefix characters have been processed,
		   find the namespace */
		bbox->ns = strcasecmp(bbox->name, "INBOX") == 0 ?
			mail_namespace_find_inbox(user->namespaces) :
			mail_namespace_find(user->namespaces, bbox->name);
		if (bbox->ns == NULL) {
			*error_r = t_strdup_printf("Namespace not found for %s",
						   bbox->name);
			return -1;
		}
		if (strcmp(bbox->name, ctx->mbox->box.vname) == 0) {
			*error_r = "Virtual mailbox can't point to itself";
			return -1;
		}
		ctx->have_mailbox_defines = TRUE;
	}

	array_push_back(&ctx->mbox->backend_boxes, &bbox);
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

	i_zero(&pattern);
	bboxes = array_get_modifiable(&mbox->backend_boxes, &count);
	p_array_init(&mbox->list_include_patterns, ctx->pool, count);
	p_array_init(&mbox->list_exclude_patterns, ctx->pool, count);
	for (i = 0; i < count; i++) {
		if (bboxes[i]->metadata_entry == NULL)
			continue;
		pattern.ns = bboxes[i]->ns;
		pattern.pattern = bboxes[i]->name;
		if (bboxes[i]->negative_match)
			dest = &mbox->list_include_patterns;
		else {
			dest = &mbox->list_exclude_patterns;
			pattern.pattern++;
		}
		array_push_back(dest, &pattern);
	}
}

static void
separate_wildcard_mailboxes(struct virtual_mailbox *mbox,
			    ARRAY_TYPE(virtual_backend_box) *wildcard_boxes,
			    ARRAY_TYPE(virtual_backend_box) *neg_boxes,
			    ARRAY_TYPE(virtual_backend_box) *metadata_boxes)
{
	struct virtual_backend_box *const *bboxes;
	ARRAY_TYPE(virtual_backend_box) *dest;
	unsigned int i, count;

	bboxes = array_get_modifiable(&mbox->backend_boxes, &count);
	t_array_init(wildcard_boxes, I_MIN(16, count));
	t_array_init(neg_boxes, 4);
	t_array_init(metadata_boxes, 4);
	for (i = 0; i < count;) {
		if (bboxes[i]->metadata_entry != NULL)
			dest = metadata_boxes;
		else if (bboxes[i]->negative_match)
			dest = neg_boxes;
		else if (bboxes[i]->glob != NULL)
			dest = wildcard_boxes;
		else {
			dest = NULL;
			i++;
		}

		if (dest != NULL) {
			array_push_back(dest, &bboxes[i]);
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
	array_push_back(&ctx->mbox->backend_boxes, &bbox);
}

static bool virtual_ns_match(struct mail_namespace *config_ns,
			     struct mail_namespace *iter_ns)
{
	/* we match only one namespace for each pattern, except with shared
	   namespaces match also autocreated children */
	if (config_ns == iter_ns)
		return TRUE;
	if (config_ns->type == iter_ns->type &&
	    (config_ns->flags & NAMESPACE_FLAG_AUTOCREATED) == 0 &&
	    (iter_ns->flags & NAMESPACE_FLAG_AUTOCREATED) != 0)
		return TRUE;
	if ((iter_ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
	    (config_ns->flags & NAMESPACE_FLAG_AUTOCREATED) != 0 &&
	    config_ns->prefix_len == 0) {
		/* prefix="" namespace was autocreated, so e.g. "*" would match
		   only that empty namespace. but we want "*" to also match
		   the inbox=yes namespace, so check it here separately. */
		return TRUE;
	}
	return FALSE;
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
			if (virtual_ns_match(boxes[i]->ns, info->ns) &&
			    imap_match(boxes[i]->glob,
				       info->vname) == IMAP_MATCH_YES) {
				*idx_r = i;
				return TRUE;
			}
		} else {
			if (strcmp(boxes[i]->name, info->vname) == 0) {
				*idx_r = i;
				return TRUE;
			}
		}
	}
	return FALSE;
}

static int virtual_config_box_metadata_match(struct mailbox *box,
					     struct virtual_backend_box *bbox,
					     const char **error_r)
{
	struct imap_metadata_transaction *imtrans;
	struct mail_attribute_value value;
	int ret;

	imtrans = imap_metadata_transaction_begin(box);
	ret = imap_metadata_get(imtrans, bbox->metadata_entry, &value);
	if (ret < 0)
		*error_r = t_strdup(imap_metadata_transaction_get_last_error(imtrans, NULL));
	if (ret > 0)
		ret = wildcard_match(value.value, bbox->metadata_value) ? 1 : 0;
	if (ret >= 0 && bbox->negative_match)
		ret = ret > 0 ? 0 : 1;
	(void)imap_metadata_transaction_commit(&imtrans, NULL, NULL);
	return ret;
}

static int
virtual_config_metadata_match(const struct mailbox_info *info,
			      ARRAY_TYPE(virtual_backend_box) *boxes_arr,
			      const char **error_r)
{
	struct virtual_backend_box *const *boxes;
	struct mailbox *box;
	unsigned int i, count;
	int ret = 1;

	boxes = array_get_modifiable(boxes_arr, &count);
	if (count == 0)
		return 1;

	box = mailbox_alloc(info->ns->list, info->vname, MAILBOX_FLAG_READONLY);
	mailbox_set_reason(box, "virtual mailbox metadata match");
	for (i = 0; i < count; i++) {
		/* break on error or match */
		if ((ret = virtual_config_box_metadata_match(box, boxes[i], error_r)) < 0 || ret > 0)
			break;
	}
	mailbox_free(&box);
	return ret;
}

static int virtual_config_expand_wildcards(struct virtual_parse_context *ctx,
					   const char **error_r)
{
	const enum mail_namespace_type iter_ns_types =
		MAIL_NAMESPACE_TYPE_MASK_ALL;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct mail_user *user = ctx->mbox->storage->storage.user;
	ARRAY_TYPE(virtual_backend_box) wildcard_boxes, neg_boxes, metadata_boxes;
	struct mailbox_list_iterate_context *iter;
	struct virtual_backend_box *const *wboxes, *const *boxp;
	const char **patterns;
	const struct mailbox_info *info;
	unsigned int i, j, count;
	int ret = 0;

	separate_wildcard_mailboxes(ctx->mbox, &wildcard_boxes,
				    &neg_boxes, &metadata_boxes);

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
		if (strcmp(info->vname, ctx->mbox->box.vname) == 0) {
			/* don't allow virtual folder to point to itself */
			continue;
		}

		if (virtual_config_match(info, &wildcard_boxes, &i) &&
		    !virtual_config_match(info, &neg_boxes, &j) &&
		    virtual_backend_box_lookup_name(ctx->mbox,
						    info->vname) == NULL) {
			ret = virtual_config_metadata_match(info, &metadata_boxes, error_r);
			if (ret < 0)
				break;
			if (ret > 0) {
				virtual_config_copy_expanded(ctx, wboxes[i],
							     info->vname);
			}
		}
	}
	for (i = 0; i < count; i++)
		mail_search_args_unref(&wboxes[i]->search_args);
	array_foreach(&neg_boxes, boxp)
		mail_search_args_unref(&(*boxp)->search_args);
	array_foreach(&metadata_boxes, boxp)
		mail_search_args_unref(&(*boxp)->search_args);
	if (mailbox_list_iter_deinit(&iter) < 0) {
		*error_r = mailbox_list_get_last_internal_error(user->namespaces->list, NULL);
		return -1;
	}
	return ret < 0 ? -1 : 0;
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
	const char *box_path, *path, *line, *error;
	unsigned int linenum = 0;
	int fd, ret = 0;

	i_array_init(&mbox->backend_boxes, 8);
	mbox->search_args_crc32 = (uint32_t)-1;

	box_path = mailbox_get_path(&mbox->box);
	path = t_strconcat(box_path, "/"VIRTUAL_CONFIG_FNAME, NULL);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno == EACCES) {
			mailbox_set_critical(&mbox->box, "%s",
				mail_error_eacces_msg("open", path));
		} else if (errno != ENOENT) {
			mailbox_set_critical(&mbox->box,
					     "open(%s) failed: %m", path);
		} else if (errno == ENOENT) {
			mail_storage_set_error(storage, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(mbox->box.vname));
		} else {
			mailbox_set_critical(&mbox->box,
				"stat(%s) failed: %m", box_path);
		}
		return -1;
	}

	i_zero(&ctx);
	ctx.sep = mail_namespaces_get_root_sep(storage->user->namespaces);
	ctx.mbox = mbox;
	ctx.pool = mbox->box.pool;
	ctx.rule = t_str_new(256);
	ctx.input = i_stream_create_fd(fd, (size_t)-1);
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
			mailbox_set_critical(&mbox->box,
					     "%s: Error at line %u: %s",
					     path, linenum, error);
			break;
		}
	}
	if (ret == 0) {
		ret = virtual_config_add_rule(&ctx, &error);
		if (ret < 0) {
			mailbox_set_critical(&mbox->box,
					     "%s: Error at line %u: %s",
					     path, linenum, error);
		}
	}

	virtual_mailbox_get_list_patterns(&ctx);
	if (ret == 0 && ctx.have_wildcards) {
		ret = virtual_config_expand_wildcards(&ctx, &error);
		if (ret < 0)
			mailbox_set_critical(&mbox->box, "%s: %s", path, error);
	}

	if (ret == 0 && !ctx.have_mailbox_defines) {
		mailbox_set_critical(&mbox->box,
				     "%s: No mailboxes defined", path);
		ret = -1;
	}
	if (ret == 0)
		virtual_config_search_args_dup(mbox);
	i_stream_unref(&ctx.input);
	i_close_fd(&fd);
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
