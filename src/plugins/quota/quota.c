/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "quota-private.h"
#include "quota-fs.h"

unsigned int quota_module_id = 0;

extern struct quota dirsize_quota;
extern struct quota dict_quota;
extern struct quota fs_quota;

static struct quota *quota_classes[] = {
	&dirsize_quota,
	&dict_quota,
#ifdef HAVE_FS_QUOTA
	&fs_quota
#endif
};
#define QUOTA_CLASS_COUNT (sizeof(quota_classes)/sizeof(quota_classes[0]))

struct quota *quota_init(const char *data)
{
	struct quota *quota;
	const char *name, *p;
	unsigned int i;

	t_push();
	p = strchr(data, ':');
	if (p == NULL) {
		name = data;
		data = "";
	} else {
		name = t_strdup_until(data, p);
		data = p+1;
	}
	for (i = 0; i < QUOTA_CLASS_COUNT; i++) {
		if (strcmp(quota_classes[i]->name, name) == 0)
			break;
	}
	t_pop();

	quota = i == QUOTA_CLASS_COUNT ? NULL :
		quota_classes[i]->init(data);
	if (quota != NULL) {
		array_create(&quota->quota_module_contexts,
			     default_pool, sizeof(void *), 5);
	}
	return quota;
}

void quota_deinit(struct quota *quota)
{
	/* make a copy, since quota is freed */
	array_t module_contexts = quota->quota_module_contexts;

	quota->deinit(quota);
	array_free(&module_contexts);
}

struct quota_root_iter *
quota_root_iter_init(struct quota *quota, struct mailbox *box)
{
	return quota->root_iter_init(quota, box);
}

struct quota_root *quota_root_iter_next(struct quota_root_iter *iter)
{
	return iter->quota->root_iter_next(iter);
}

int quota_root_iter_deinit(struct quota_root_iter *iter)
{
	return iter->quota->root_iter_deinit(iter);
}

struct quota_root *quota_root_lookup(struct quota *quota, const char *name)
{
	return quota->root_lookup(quota, name);
}

const char *quota_root_get_name(struct quota_root *root)
{
	return root->quota->root_get_name(root);
}

const char *const *quota_root_get_resources(struct quota_root *root)
{
	return root->quota->root_get_resources(root);
}

int quota_root_create(struct quota *quota, const char *name,
		      struct quota_root **root_r)
{
	return quota->root_create(quota, name, root_r);
}

int quota_get_resource(struct quota_root *root, const char *name,
		       uint64_t *value_r, uint64_t *limit_r)
{
	return root->quota->get_resource(root, name, value_r, limit_r);
}

int quota_set_resource(struct quota_root *root,
		       const char *name, uint64_t value)
{
	return root->quota->set_resource(root, name, value);
}

struct quota_transaction_context *quota_transaction_begin(struct quota *quota)
{
	return quota->transaction_begin(quota);
}

int quota_transaction_commit(struct quota_transaction_context *ctx)
{
	return ctx->quota->transaction_commit(ctx);
}

void quota_transaction_rollback(struct quota_transaction_context *ctx)
{
	ctx->quota->transaction_rollback(ctx);
}

int quota_try_alloc(struct quota_transaction_context *ctx,
		    struct mail *mail, int *too_large_r)
{
	return ctx->quota->try_alloc(ctx, mail, too_large_r);
}

void quota_alloc(struct quota_transaction_context *ctx, struct mail *mail)
{
	ctx->quota->alloc(ctx, mail);
}

void quota_free(struct quota_transaction_context *ctx, struct mail *mail)
{
	ctx->quota->free(ctx, mail);
}

const char *quota_last_error(struct quota *quota)
{
	return quota->last_error(quota);
}
