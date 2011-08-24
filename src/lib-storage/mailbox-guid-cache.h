#ifndef MAILBOX_GUID_CACHE_H
#define MAILBOX_GUID_CACHE_H

int mailbox_guid_cache_find(struct mailbox_list *list, const guid_128_t guid,
			    const char **vname_r);
void mailbox_guid_cache_refresh(struct mailbox_list *list);

#endif
