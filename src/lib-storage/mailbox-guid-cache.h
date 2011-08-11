#ifndef MAILBOX_GUID_CACHE_H
#define MAILBOX_GUID_CACHE_H

int mailbox_guid_cache_find(struct mailbox_list *list,
			    uint8_t guid[MAIL_GUID_128_SIZE],
			    const char **vname_r);
void mailbox_guid_cache_refresh(struct mailbox_list *list);

#endif
