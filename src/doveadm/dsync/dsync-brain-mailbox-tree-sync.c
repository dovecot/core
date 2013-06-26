/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "dsync-mailbox-tree.h"
#include "dsync-brain-private.h"

static int
sync_create_box(struct dsync_brain *brain, struct mailbox *box,
		const guid_128_t mailbox_guid, uint32_t uid_validity)
{
	struct mailbox_metadata metadata;
	struct mailbox_update update;
	enum mail_error error;
	const char *errstr;
	int ret;

	memset(&update, 0, sizeof(update));
	memcpy(update.mailbox_guid, mailbox_guid, sizeof(update.mailbox_guid));
	update.uid_validity = uid_validity;

	if (mailbox_create(box, &update, FALSE) < 0) {
		errstr = mailbox_get_last_error(box, &error);
		if (error != MAIL_ERROR_EXISTS) {
			i_error("Can't create mailbox %s: %s",
				mailbox_get_vname(box), errstr);
			return -1;
		}
	}
	/* sync the mailbox so we can look up its latest status */
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("Can't sync mailbox %s: %s",
			mailbox_get_vname(box),
			mailbox_get_last_error(box, NULL));
		return -1;
	}

	/* verify that the GUID is what we wanted. if it's not, it probably
	   means that the mailbox had already been created. then we'll use the
	   GUID that is higher.

	   mismatching UIDVALIDITY is handled later, because we choose it by
	   checking which mailbox has more messages */
	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) < 0) {
		i_error("Can't get mailbox GUID %s: %s",
			mailbox_get_vname(box),
			mailbox_get_last_error(box, NULL));
		return -1;
	}

	ret = memcmp(mailbox_guid, metadata.guid, sizeof(metadata.guid));
	if (ret > 0) {
		if (brain->debug) {
			i_debug("brain %c: Changing mailbox %s GUID %s -> %s",
				brain->master_brain ? 'M' : 'S',
				mailbox_get_vname(box),
				guid_128_to_string(metadata.guid),
				guid_128_to_string(mailbox_guid));
		}
		memset(&update, 0, sizeof(update));
		memcpy(update.mailbox_guid, mailbox_guid,
		       sizeof(update.mailbox_guid));
		if (mailbox_update(box, &update) < 0) {
			i_error("Can't update mailbox GUID %s: %s",
				mailbox_get_vname(box),
				mailbox_get_last_error(box, NULL));
			return -1;
		}
		/* verify that the update worked */
		if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID,
					 &metadata) < 0) {
			i_error("Can't get mailbox GUID %s: %s",
				mailbox_get_vname(box),
				mailbox_get_last_error(box, NULL));
			return -1;
		}
		if (memcmp(mailbox_guid, metadata.guid,
			   sizeof(metadata.guid)) != 0) {
			i_error("Backend didn't update mailbox %s GUID",
				mailbox_get_vname(box));
			return -1;
		}
	} else if (ret < 0) {
		if (brain->debug) {
			i_debug("brain %c: Other brain should change mailbox "
				"%s GUID %s -> %s",
				brain->master_brain ? 'M' : 'S',
				mailbox_get_vname(box),
				guid_128_to_string(mailbox_guid),
				guid_128_to_string(metadata.guid));
		}
	}
	return 0;
}

int dsync_brain_mailbox_tree_sync_change(struct dsync_brain *brain,
			const struct dsync_mailbox_tree_sync_change *change)
{
	struct mailbox *box = NULL, *destbox;
	const char *errstr, *func_name = NULL, *storage_name;
	enum mail_error error;
	int ret = -1;

	if (brain->backup_send) {
		i_assert(brain->no_backup_overwrite);
		return 0;
	}

	switch (change->type) {
	case DSYNC_MAILBOX_TREE_SYNC_TYPE_DELETE_BOX:
		/* make sure we're deleting the correct mailbox */
		ret = dsync_brain_mailbox_alloc(brain, change->mailbox_guid,
						&box);
		if (ret <= 0) {
			brain->changes_during_sync = TRUE;
			return ret;
		}
		break;
	case DSYNC_MAILBOX_TREE_SYNC_TYPE_DELETE_DIR:
		storage_name = mailbox_list_get_storage_name(change->ns->list,
							     change->full_name);
		if (mailbox_list_delete_dir(change->ns->list, storage_name) == 0)
			return 0;

		errstr = mailbox_list_get_last_error(change->ns->list, &error);
		if (error == MAIL_ERROR_NOTFOUND ||
		    error == MAIL_ERROR_EXISTS) {
			brain->changes_during_sync = TRUE;
			return 0;
		} else {
			i_error("Mailbox sync: mailbox_list_delete_dir failed: %s",
				errstr);
			return -1;
		}
	default:
		box = mailbox_alloc(change->ns->list, change->full_name, 0);
		break;
	}
	switch (change->type) {
	case DSYNC_MAILBOX_TREE_SYNC_TYPE_CREATE_BOX:
		ret = sync_create_box(brain, box, change->mailbox_guid,
				      change->uid_validity);
		mailbox_free(&box);
		return ret;
	case DSYNC_MAILBOX_TREE_SYNC_TYPE_CREATE_DIR:
		ret = mailbox_create(box, NULL, TRUE);
		func_name = "mailbox_create";
		break;
	case DSYNC_MAILBOX_TREE_SYNC_TYPE_DELETE_BOX:
		ret = mailbox_delete(box);
		func_name = "mailbox_delete";
		break;
	case DSYNC_MAILBOX_TREE_SYNC_TYPE_DELETE_DIR:
		i_unreached();
	case DSYNC_MAILBOX_TREE_SYNC_TYPE_RENAME:
		destbox = mailbox_alloc(change->ns->list,
					change->rename_dest_name, 0);
		ret = mailbox_rename(box, destbox);
		func_name = "mailbox_rename";
		mailbox_free(&destbox);
		break;
	case DSYNC_MAILBOX_TREE_SYNC_TYPE_SUBSCRIBE:
		ret = mailbox_set_subscribed(box, TRUE);
		func_name = "mailbox_set_subscribed";
		break;
	case DSYNC_MAILBOX_TREE_SYNC_TYPE_UNSUBSCRIBE:
		ret = mailbox_set_subscribed(box, FALSE);
		func_name = "mailbox_set_subscribed";
		break;
	}
	if (ret < 0) {
		errstr = mailbox_get_last_error(box, &error);
		if (error == MAIL_ERROR_EXISTS ||
		    error == MAIL_ERROR_NOTFOUND) {
			/* mailbox was already created or was already deleted.
			   let the next sync figure out what to do */
			brain->changes_during_sync = TRUE;
			ret = 0;
		} else {
			i_error("Mailbox %s sync: %s failed: %s",
				mailbox_get_vname(box), func_name, errstr);
		}
	}
	mailbox_free(&box);
	return ret;
}
