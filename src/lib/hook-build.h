/* Copyright (c) 2017 Dovecot authors, see the included COPYING file */
#ifndef HOOK_BUILD_H
#define HOOK_BUILD_H 1

struct hook_build_context;
struct hook_stack;

/* Initialize new hook building context, vfuncs should point to
   the functions table that is being manipulated, and size should be
   the size of this table. */
struct hook_build_context *hook_build_init(void (**vfuncs)(), size_t size);

/* This is called after a hook may have updated vfuncs */
void hook_build_update(struct hook_build_context *ctx, void *_vlast);

/* Free memory used by build context */
void hook_build_deinit(struct hook_build_context **_ctx);

#endif
