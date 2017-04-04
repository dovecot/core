/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "hook-build.h"

struct hook_stack {
	struct hook_stack *prev, *next;

	/* Pointer to vfuncs struct. This assumes that a struct containing
	   function pointers equals to an array of function pointers. Not
	   ANSI-C, but should work in all OSes supported by Dovecot. Much
	   easier anyway than doing this work manually.. */
	void (**vfuncs)();
	/* nonzero in the areas where vfuncs has been changed */
	void (**mask)();
};

struct hook_build_context {
	pool_t pool;
	/* size of the vfuncs struct */
	size_t size;
	/* number of function pointers in the struct */
	unsigned int count;

	struct hook_stack *head, *tail;
};

static void hook_build_append(struct hook_build_context *ctx, void (**vfuncs)())
{
	struct hook_stack *stack;

	stack = p_new(ctx->pool, struct hook_stack, 1);
	stack->vfuncs = vfuncs;
	stack->mask = p_malloc(ctx->pool, ctx->size);
	DLLIST2_APPEND(&ctx->head, &ctx->tail, stack);
}

struct hook_build_context *hook_build_init(void (**vfuncs)(), size_t size)
{
	struct hook_build_context *ctx;
	pool_t pool;

	i_assert((size % sizeof(void (*)())) == 0);

	pool = pool_alloconly_create("hook build context", 2048);
	ctx = p_new(pool, struct hook_build_context, 1);
	ctx->pool = pool;
	ctx->size = size;
	ctx->count = size / sizeof(void (*)());
	hook_build_append(ctx, vfuncs);
	return ctx;
}

static void
hook_update_mask(struct hook_build_context *ctx, struct hook_stack *stack,
		 void (**vlast)())
{
	unsigned int i;

	for (i = 0; i < ctx->count; i++) {
		if (stack->vfuncs[i] != vlast[i]) {
			i_assert(stack->vfuncs[i] != NULL);
			stack->mask[i] = stack->vfuncs[i];
		}
	}
}

static void
hook_copy_stack(struct hook_build_context *ctx, struct hook_stack *stack)
{
	unsigned int i;

	i_assert(stack->next != NULL);

	for (i = 0; i < ctx->count; i++) {
		if (stack->mask[i] == NULL) {
			stack->vfuncs[i] = stack->next->vfuncs[i];
			stack->mask[i] = stack->next->mask[i];
		}
	}
}

void hook_build_update(struct hook_build_context *ctx, void *_vlast)
{
	void (**vlast)() = _vlast;
	struct hook_stack *stack;

	if (ctx->tail->vfuncs == vlast) {
		/* no vfuncs overridden */
		return;
	}

	/* ctx->vfuncs_stack->vfuncs points to the root vfuncs,
	   ctx->vfuncs_stack->next->vfuncs points to the first super function
	   that is being called, and so on.

	   the previous plugin added its vfuncs to the stack tail.
	   vlast contains the previous plugin's super vfuncs, which is where
	   the next plugin should put its own vfuncs.

	   first we'll need to figure out what vfuncs the previous plugin
	   changed and update the mask */
	hook_update_mask(ctx, ctx->tail, vlast);

	/* now go up in the stack as long as the mask isn't set,
	   and update the vfuncs */
	for (stack = ctx->tail->prev; stack != NULL; stack = stack->prev)
		hook_copy_stack(ctx, stack);

	/* add vlast to stack */
	hook_build_append(ctx, vlast);
}

void hook_build_deinit(struct hook_build_context **_ctx)
{
	struct hook_build_context *ctx = *_ctx;
	*_ctx = NULL;
	pool_unref(&ctx->pool);
}
