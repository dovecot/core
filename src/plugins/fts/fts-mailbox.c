/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "fts-mailbox.h"
#include "../virtual/virtual-storage.h"

bool fts_mailbox_get_virtual_uid(struct mailbox *box,
				 const char *backend_mailbox,
				 uint32_t backend_uidvalidity,
				 uint32_t backend_uid, uint32_t *uid_r)
{
	struct virtual_mailbox *vbox;

	if (strcmp(box->storage->name, VIRTUAL_STORAGE_NAME) != 0)
		return FALSE;

	vbox = (struct virtual_mailbox *)box;
	return vbox->vfuncs.get_virtual_uid(box, backend_mailbox,
					    backend_uidvalidity,
					    backend_uid, uid_r);
}

void fts_mailbox_get_virtual_backend_boxes(struct mailbox *box,
					   ARRAY_TYPE(mailboxes) *mailboxes,
					   bool only_with_msgs)
{
	struct virtual_mailbox *vbox;

	if (strcmp(box->storage->name, VIRTUAL_STORAGE_NAME) != 0)
		array_append(mailboxes, &box, 1);
	else {
		vbox = (struct virtual_mailbox *)box;
		vbox->vfuncs.get_virtual_backend_boxes(box, mailboxes,
						       only_with_msgs);
	}
}

void fts_mailbox_get_virtual_box_patterns(struct mailbox *box,
				ARRAY_TYPE(mailbox_virtual_patterns) *includes,
				ARRAY_TYPE(mailbox_virtual_patterns) *excludes)
{
	struct virtual_mailbox *vbox;

	if (strcmp(box->storage->name, VIRTUAL_STORAGE_NAME) != 0) {
		struct mailbox_virtual_pattern pat;

		memset(&pat, 0, sizeof(pat));
		pat.ns = mailbox_list_get_namespace(box->list);
		pat.pattern = box->name;
		array_append(includes, &pat, 1);
	} else {
		vbox = (struct virtual_mailbox *)box;
		vbox->vfuncs.get_virtual_box_patterns(box, includes, excludes);
	}
}
