/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mailbox-list-private.h"
#include "virtual-storage.h"
#include "virtual-plugin.h"

#define VIRTUAL_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, virtual_mailbox_list_module)

struct virtual_mailbox_list {
	union mailbox_list_module_context module_ctx;
};

static MODULE_CONTEXT_DEFINE_INIT(virtual_mailbox_list_module,
				  &mailbox_list_module_register);

static int
virtual_get_storage(struct mailbox_list **list, const char **vname,
		    enum mailbox_list_get_storage_flags flags,
		    struct mail_storage **storage_r)
{
	struct virtual_mailbox_list *vlist = VIRTUAL_LIST_CONTEXT(*list);

	if (vlist->module_ctx.super.get_storage(list, vname, flags, storage_r) < 0)
		return -1;

	if ((flags & MAILBOX_LIST_GET_STORAGE_FLAG_SAVEONLY) == 0 ||
	    (*storage_r)->storage_class != &virtual_storage)
		return 0;

	/* saving to a virtual mailbox - change the list/vname/storage to the
	   backend mailbox. */
	struct mailbox *vbox =
		mailbox_alloc(*list, *vname, flags & ENUM_NEGATE(MAILBOX_FLAG_SAVEONLY));
	i_assert(strcmp(vbox->storage->name, VIRTUAL_STORAGE_NAME) == 0);
	struct virtual_mailbox *mbox = container_of(vbox, struct virtual_mailbox, box);
	const char *path;
	int ret = mailbox_get_path_to(vbox, MAILBOX_LIST_PATH_TYPE_MAILBOX, &path);
	if (ret > 0)
		ret = virtual_config_read(mbox);
	if (ret == 0 && mbox->save_bbox != NULL) {
		struct mail_namespace *ns =
			mail_namespace_find((*storage_r)->user->namespaces,
					    mbox->save_bbox->name);
		*list = ns->list;
		*vname = t_strdup(mbox->save_bbox->name);
		if (mailbox_list_get_storage(list, vname, flags, storage_r) < 0)
			ret = -1;
	}
	mailbox_free(&vbox);
	return ret;
}

void virtual_mailbox_list_created(struct mailbox_list *list)
{
	struct virtual_mailbox_list *vlist;
	struct mailbox_list_vfuncs *v = list->vlast;

	vlist = p_new(list->pool, struct virtual_mailbox_list, 1);
	vlist->module_ctx.super = *v;
	list->vlast = &vlist->module_ctx.super;
	v->get_storage = virtual_get_storage;

	MODULE_CONTEXT_SET(list, virtual_mailbox_list_module, vlist);
}
