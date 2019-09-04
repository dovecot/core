/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-private.h"
#include "notify-plugin.h"
#include "str.h"

#include "push-notification-drivers.h"
#include "push-notification-events.h"
#include "push-notification-events-rfc5423.h"
#include "push-notification-plugin.h"
#include "push-notification-triggers.h"
#include "push-notification-txn-mbox.h"
#include "push-notification-txn-msg.h"


#define PUSH_NOTIFICATION_CONFIG "push_notification_driver"
#define PUSH_NOTIFICATION_CONFIG_OLD "push_notification_backend"
#define PUSH_NOTIFICATION_EVENT_FINISHED "push_notification_finished"

#define PUSH_NOTIFICATION_USER_CONTEXT(obj) \
        MODULE_CONTEXT_REQUIRE(obj, push_notification_user_module)
static MODULE_CONTEXT_DEFINE_INIT(push_notification_user_module,
                                  &mail_user_module_register);
static struct ioloop *main_ioloop;

struct event_category event_category_push_notification = {
	.name = "push_notification",
};

struct event_category *push_notification_get_event_category(void)
{
	return &event_category_push_notification;
}

struct push_notification_event *
push_notification_get_event_messagenew(void)
{
	return &push_notification_event_messagenew;
}

static void
push_notification_transaction_init(struct push_notification_txn *ptxn)
{
    struct push_notification_driver_txn *dtxn;
    struct push_notification_driver_user **duser;
    struct mail_storage *storage;

    if (ptxn->initialized) {
        return;
    }

    ptxn->initialized = TRUE;

    storage = mailbox_get_storage(ptxn->mbox);
    if (storage->user->autocreated &&
        (strcmp(storage->name, "raw") == 0)) {
        /* no notifications for autocreated raw users */
        return;
    }

    array_foreach_modifiable(&ptxn->puser->driverlist->drivers, duser) {
        dtxn = p_new(ptxn->pool, struct push_notification_driver_txn, 1);
        dtxn->duser = *duser;
        dtxn->ptxn = ptxn;

        if ((dtxn->duser->driver->v.begin_txn == NULL) ||
            dtxn->duser->driver->v.begin_txn(dtxn)) {
            array_push_back(&ptxn->drivers, &dtxn);
        }
    }
}

static struct push_notification_txn *
push_notification_transaction_create(struct mailbox *box,
                                     struct mailbox_transaction_context *t)
{
    pool_t pool;
    struct push_notification_txn *ptxn;
    struct mail_storage *storage;

    pool = pool_alloconly_create("push notification transaction", 2048);

    ptxn = p_new(pool, struct push_notification_txn, 1);
    ptxn->mbox = box;
    storage = mailbox_get_storage(box);
    ptxn->muser = mail_storage_get_user(storage);
    ptxn->pool = pool;
    ptxn->puser = PUSH_NOTIFICATION_USER_CONTEXT(ptxn->muser);
    ptxn->t = t;
    ptxn->trigger = PUSH_NOTIFICATION_EVENT_TRIGGER_NONE;
    ptxn->event = event_create(ptxn->muser->event);
    event_add_category(ptxn->event, &event_category_push_notification);
    event_set_append_log_prefix(ptxn->event, "push-notification: ");
    p_array_init(&ptxn->drivers, pool, 4);

    return ptxn;
}

static void push_notification_transaction_end
(struct push_notification_txn *ptxn, bool success)
{
    struct push_notification_driver_txn **dtxn;

    if (ptxn->initialized) {
        array_foreach_modifiable(&ptxn->drivers, dtxn) {
            if ((*dtxn)->duser->driver->v.end_txn != NULL) {
                (*dtxn)->duser->driver->v.end_txn(*dtxn, success);
            }
        }
    }

    struct event_passthrough *e = event_create_passthrough(ptxn->event)->
        set_name(PUSH_NOTIFICATION_EVENT_FINISHED);
    /* emit event */
    e_debug(e->event(), "Push notification transaction completed");
    event_unref(&ptxn->event);
    pool_unref(&ptxn->pool);
}

static void push_notification_transaction_commit
(void *txn, struct mail_transaction_commit_changes *changes)
{
    struct push_notification_txn *ptxn = (struct push_notification_txn *)txn;
    struct ioloop *prev_ioloop = current_ioloop;

    /* Make sure we're not in just any random ioloop, which could get
       destroyed soon. This way the push-notification drivers can do async
       operations that finish in the main ioloop. */
    io_loop_set_current(main_ioloop);
    if (changes == NULL) {
        push_notification_txn_mbox_end(ptxn);
    } else {
        push_notification_txn_msg_end(ptxn, changes);
    }

    push_notification_transaction_end(ptxn, TRUE);
    io_loop_set_current(prev_ioloop);
}

static void push_notification_mailbox_create(struct mailbox *box)
{
    struct push_notification_txn *ptxn;

    ptxn = push_notification_transaction_create(box, NULL);
    push_notification_transaction_init(ptxn);
    push_notification_trigger_mbox_create(ptxn, box, NULL);
    push_notification_transaction_commit(ptxn, NULL);
}

static void push_notification_mailbox_delete(void *txn ATTR_UNUSED,
                                             struct mailbox *box)
{
    struct push_notification_txn *ptxn;

    ptxn = push_notification_transaction_create(box, NULL);
    push_notification_transaction_init(ptxn);
    push_notification_trigger_mbox_delete(ptxn, box, NULL);
    push_notification_transaction_commit(ptxn, NULL);
}

static void push_notification_mailbox_rename(struct mailbox *src,
                                             struct mailbox *dest)
{
    struct push_notification_txn *ptxn;

    ptxn = push_notification_transaction_create(dest, NULL);
    push_notification_transaction_init(ptxn);
    push_notification_trigger_mbox_rename(ptxn, src, dest, NULL);
    push_notification_transaction_commit(ptxn, NULL);
}

static void push_notification_mailbox_subscribe(struct mailbox *box,
                                                bool subscribed)
{
    struct push_notification_txn *ptxn;

    ptxn = push_notification_transaction_create(box, NULL);
    push_notification_transaction_init(ptxn);
    push_notification_trigger_mbox_subscribe(ptxn, box, subscribed, NULL);
    push_notification_transaction_commit(ptxn, NULL);
}

static void push_notification_mail_save(void *txn, struct mail *mail)
{
    struct push_notification_txn *ptxn = txn;

    push_notification_transaction_init(ptxn);

    /* POST_SESSION means MTA delivery. */
    if ((mail->box->flags & MAILBOX_FLAG_POST_SESSION) != 0) {
        push_notification_trigger_msg_save_new(ptxn, mail, NULL);
    } else {
        push_notification_trigger_msg_save_append(ptxn, mail, NULL);
    }
}

static void push_notification_mail_copy(void *txn,
                                        struct mail *src ATTR_UNUSED,
                                        struct mail *dest)
{
    push_notification_mail_save(txn, dest);
}

static void push_notification_mail_expunge(void *txn, struct mail *mail)
{
    struct push_notification_txn *ptxn = txn;

    push_notification_transaction_init(ptxn);
    push_notification_trigger_msg_save_expunge(txn, mail, NULL);
}

static void
push_notification_mail_update_flags(void *txn, struct mail *mail,
                                    enum mail_flags old_flags)
{
    struct push_notification_txn *ptxn = txn;

    push_notification_transaction_init(ptxn);
    push_notification_trigger_msg_flag_change(txn, mail, NULL, old_flags);
}

static void
push_notification_mail_update_keywords(void *txn, struct mail *mail,
                                       const char *const *old_keywords)
{
    struct push_notification_txn *ptxn = txn;

    push_notification_transaction_init(ptxn);
    push_notification_trigger_msg_keyword_change(txn, mail, NULL, old_keywords);
}

static void *
push_notification_transaction_begin(struct mailbox_transaction_context *t)
{
    return push_notification_transaction_create(mailbox_transaction_get_mailbox(t), t);
}

static void push_notification_transaction_rollback(void *txn)
{
    struct push_notification_txn *ptxn = txn;

    push_notification_transaction_end(ptxn, FALSE);
}

static void
push_notification_config_init(const char *config_name,
                              struct mail_user *user,
                              struct push_notification_driver_list *dlist)
{
    struct push_notification_driver_user *duser;
    const char *env;
    unsigned int i;
    string_t *root_name;

    root_name = t_str_new(32);
    str_append(root_name, config_name);

    for (i = 2;; i++) {
        env = mail_user_plugin_getenv(user, str_c(root_name));
        if ((env == NULL) || (*env == '\0')) {
            break;
        }

        if (push_notification_driver_init(user, env, user->pool, &duser) < 0) {
            break;
        }

        // Add driver.
        array_push_back(&dlist->drivers, &duser);

        str_truncate(root_name, strlen(config_name));
        str_printfa(root_name, "%d", i);
    }
}

static struct push_notification_driver_list *
push_notification_driver_list_init(struct mail_user *user)
{
    struct push_notification_driver_list *dlist;

    dlist = p_new(user->pool, struct push_notification_driver_list, 1);
    p_array_init(&dlist->drivers, user->pool, 4);

    push_notification_config_init(PUSH_NOTIFICATION_CONFIG, user, dlist);

    if (array_is_empty(&dlist->drivers)) {
        /* Support old configuration (it was available at time initial OX
         * driver was first released). */
        push_notification_config_init(PUSH_NOTIFICATION_CONFIG_OLD, user,
                                      dlist);
    }
    return dlist;
}

static void push_notification_user_deinit(struct mail_user *user)
{
    struct push_notification_user *puser = PUSH_NOTIFICATION_USER_CONTEXT(user);
    struct push_notification_driver_list *dlist = puser->driverlist;
    struct push_notification_driver_user **duser;
    struct ioloop *prev_ioloop = current_ioloop;

    /* Make sure we're in the main ioloop, so if the deinit/cleanup moves any
       I/Os or timeouts they won't get moved to some temporary ioloop. */
    io_loop_set_current(main_ioloop);

    array_foreach_modifiable(&dlist->drivers, duser) {
        if ((*duser)->driver->v.deinit != NULL) {
            (*duser)->driver->v.deinit(*duser);
        }

        if ((*duser)->driver->v.cleanup != NULL) {
            (*duser)->driver->v.cleanup();
        }
    }
    io_loop_set_current(prev_ioloop);

    puser->module_ctx.super.deinit(user);
}

static void push_notification_user_created(struct mail_user *user)
{
    struct mail_user_vfuncs *v = user->vlast;
    struct push_notification_user *puser;

    puser = p_new(user->pool, struct push_notification_user, 1);
    puser->module_ctx.super = *v;
    user->vlast = &puser->module_ctx.super;
    v->deinit = push_notification_user_deinit;
    puser->driverlist = push_notification_driver_list_init(user);

    MODULE_CONTEXT_SET(user, push_notification_user_module, puser);
}


/* Plugin interface. */

const char *push_notification_plugin_version = DOVECOT_ABI_VERSION;
const char *push_notification_plugin_dependencies[] = { "notify", NULL };

extern struct push_notification_driver push_notification_driver_dlog;
extern struct push_notification_driver push_notification_driver_ox;

static struct notify_context *push_notification_ctx;

static const struct notify_vfuncs push_notification_vfuncs = {
    /* Mailbox Events */
    .mailbox_create = push_notification_mailbox_create,
    .mailbox_delete_commit = push_notification_mailbox_delete,
    .mailbox_rename = push_notification_mailbox_rename,
    .mailbox_set_subscribed = push_notification_mailbox_subscribe,

    /* Mail Events */
    .mail_copy = push_notification_mail_copy,
    .mail_save = push_notification_mail_save,
    .mail_expunge = push_notification_mail_expunge,
    .mail_update_flags = push_notification_mail_update_flags,
    .mail_update_keywords = push_notification_mail_update_keywords,
    .mail_transaction_begin = push_notification_transaction_begin,
    .mail_transaction_commit = push_notification_transaction_commit,
    .mail_transaction_rollback = push_notification_transaction_rollback
};

static struct mail_storage_hooks push_notification_storage_hooks = {
    .mail_user_created = push_notification_user_created
};

void push_notification_plugin_init(struct module *module)
{
    push_notification_ctx = notify_register(&push_notification_vfuncs);
    mail_storage_hooks_add(module, &push_notification_storage_hooks);

    push_notification_driver_register(&push_notification_driver_dlog);
    push_notification_driver_register(&push_notification_driver_ox);

    push_notification_event_register_rfc5423_events();
    main_ioloop = current_ioloop;
    i_assert(main_ioloop != NULL);
}

void push_notification_plugin_deinit(void)
{
    push_notification_driver_unregister(&push_notification_driver_dlog);
    push_notification_driver_unregister(&push_notification_driver_ox);

    push_notification_event_unregister_rfc5423_events();
    mail_storage_hooks_remove(&push_notification_storage_hooks);
    notify_unregister(push_notification_ctx);
}
