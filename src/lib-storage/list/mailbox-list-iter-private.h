#ifndef MAILBOX_LIST_ITER_PRIVATE_H
#define MAILBOX_LIST_ITER_PRIVATE_H

#include "mailbox-list-iter.h"

struct autocreate_box {
	const char *name;
	const struct mailbox_settings *set;
	enum mailbox_info_flags flags;
	bool child_listed;
};

ARRAY_DEFINE_TYPE(mailbox_settings, struct mailbox_settings *);
struct mailbox_list_autocreate_iterate_context {
	unsigned int idx;
	struct mailbox_info new_info;
	ARRAY(struct autocreate_box) boxes;
	ARRAY_TYPE(mailbox_settings) box_sets;
	ARRAY_TYPE(mailbox_settings) all_ns_box_sets;
	bool listing_autoboxes:1;
};

#endif
