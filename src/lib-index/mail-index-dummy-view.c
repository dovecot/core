/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-index-private.h"
#include "mail-index-view-private.h"

static void dummy_view_close(struct mail_index_view *view ATTR_UNUSED)
{
	i_assert(view->refcount == 0);

	array_free(&view->module_contexts);
	i_free(view);
}

static uint32_t
dummy_view_get_message_count(struct mail_index_view *view ATTR_UNUSED)
{
	return (uint32_t)-3;
}

static struct mail_index_view_vfuncs dummy_view_vfuncs = {
	dummy_view_close,
	dummy_view_get_message_count,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

struct mail_index_view *mail_index_dummy_view_open(struct mail_index *index)
{
	struct mail_index_view *view;

	view = i_new(struct mail_index_view, 1);
	view->refcount = 1;
	view->v = dummy_view_vfuncs;
	view->index = index;
	i_array_init(&view->module_contexts,
		     I_MIN(5, mail_index_module_register.id));
	return view;
}
