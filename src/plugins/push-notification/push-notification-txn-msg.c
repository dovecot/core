/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "mail-storage-private.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-txn-msg.h"


struct push_notification_txn_msg *
push_notification_txn_msg_create(struct push_notification_txn *txn,
                                 struct mail *mail)
{
    struct push_notification_txn_msg *msg = NULL;

    if (hash_table_is_created(txn->messages)) {
        msg = hash_table_lookup(txn->messages,
                                POINTER_CAST(mail->seq));
    } else {
        hash_table_create_direct(&txn->messages, txn->pool, 4);
    }

    if (msg == NULL) {
        msg = p_new(txn->pool, struct push_notification_txn_msg, 1);
        msg->mailbox = mailbox_get_vname(mail->box);
        /* Save sequence number - used to determine UID later. */
	if (mail->uid == 0)
		msg->save_idx = txn->t->save_count;
	else
		msg->save_idx = UINT_MAX;
        msg->uid = mail->uid;

        hash_table_insert(txn->messages, POINTER_CAST(mail->seq),
                          msg);
    }

    return msg;
}

void
push_notification_txn_msg_end(struct push_notification_txn *ptxn,
                              struct mail_transaction_commit_changes *changes)
{
    struct hash_iterate_context *hiter;
    void *key;
    struct push_notification_driver_txn **dtxn;
    struct seq_range_iter siter;
    struct mailbox_status status;
    uint32_t uid, uid_validity;
    struct push_notification_txn_msg *value;

    if (!hash_table_is_created(ptxn->messages)) {
        return;
    }

    hiter = hash_table_iterate_init(ptxn->messages);
    seq_range_array_iter_init(&siter, &changes->saved_uids);

    /* uid_validity is only set in changes if message is new. */
    if (changes->uid_validity == 0) {
        mailbox_get_open_status(ptxn->mbox, STATUS_UIDVALIDITY, &status);
        uid_validity = status.uidvalidity;
    } else {
        uid_validity = changes->uid_validity;
    }

    while (hash_table_iterate(hiter, ptxn->messages, &key, &value)) {
        if (value->uid == 0) {
            if (seq_range_array_iter_nth(&siter, value->save_idx, &uid)) {
                value->uid = uid;
            }
        } else
		i_assert(value->save_idx == UINT_MAX);
        value->uid_validity = uid_validity;

        array_foreach_modifiable(&ptxn->drivers, dtxn) {
            if ((*dtxn)->duser->driver->v.process_msg != NULL) {
                (*dtxn)->duser->driver->v.process_msg(*dtxn, value);
            }
        }

        push_notification_txn_msg_deinit_eventdata(value);
    }

    hash_table_iterate_deinit(&hiter);
    hash_table_destroy(&ptxn->messages);
}

void *
push_notification_txn_msg_get_eventdata(struct push_notification_txn_msg *msg,
                                        const char *event_name)
{
    struct push_notification_txn_event **mevent;

    if (array_is_created(&msg->eventdata)) {
        array_foreach_modifiable(&msg->eventdata, mevent) {
            if (strcmp((*mevent)->event->event->name, event_name) == 0) {
                return (*mevent)->data;
            }
        }
    }

    return NULL;
}

void
push_notification_txn_msg_set_eventdata(struct push_notification_txn *txn,
                                        struct push_notification_txn_msg *msg,
                                        struct push_notification_event_config *event,
                                        void *data)
{
    struct push_notification_txn_event *mevent;

    if (!array_is_created(&msg->eventdata)) {
        p_array_init(&msg->eventdata, txn->pool, 4);
    }

    mevent = p_new(txn->pool, struct push_notification_txn_event, 1);
    mevent->data = data;
    mevent->event = event;

    array_push_back(&msg->eventdata, &mevent);
}

void
push_notification_txn_msg_deinit_eventdata(struct push_notification_txn_msg *msg)
{
    struct push_notification_txn_event **mevent;

    if (array_is_created(&msg->eventdata)) {
        array_foreach_modifiable(&msg->eventdata, mevent) {
            if (((*mevent)->data != NULL) &&
                ((*mevent)->event->event->msg.free_msg != NULL)) {
                (*mevent)->event->event->msg.free_msg(*mevent);
            }
        }
    }
}
