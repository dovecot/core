/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#ifndef PUSH_NOTIFICATION_DRIVERS_H
#define PUSH_NOTIFICATION_DRIVERS_H


#include "mail-user.h"
#include "push-notification-triggers.h"

struct mail_user;
struct push_notification_driver_config;
struct push_notification_driver_txn;
struct push_notification_driver_user;
struct push_notification_txn_mbox;
struct push_notification_txn_msg;


HASH_TABLE_DEFINE_TYPE(push_notification_config, const char *, const char *);
HASH_TABLE_DEFINE_TYPE(push_notification_msgs, void *,
                       struct push_notification_txn_msg *);


struct push_notification_driver_vfuncs {
    /* Init driver. Config (from plugin configuration) is parsed once (no
     * user variable substitutions). Return 0 on success, or -1 if this
     * driver should be disabled (or on error). */
    int (*init)(struct push_notification_driver_config *config,
                struct mail_user *user, pool_t pool, void **context,
                const char **error_r);
    /* Called at the beginning of a notification transaction. Return TRUE on
     * success, or FALSE if this driver should be ignored for this
     * transaction. */
    bool (*begin_txn)(struct push_notification_driver_txn *dtxn);
    /* Called once for every mailbox processed. */
    void (*process_mbox)(struct push_notification_driver_txn *dtxn,
                         struct push_notification_txn_mbox *mbox);
    /* Called once for every message processed. */
    void (*process_msg)(struct push_notification_driver_txn *dtxn,
                        struct push_notification_txn_msg *msg);
    /* Called at the end of a successful notification transaction. */
    void (*end_txn)(struct push_notification_driver_txn *dtxn, bool success);
    /* Called when plugin is deinitialized. */
    void (*deinit)(struct push_notification_driver_user *duser);
    /* Called to cleanup any global resources used in plugin. */
    void (*cleanup)(void);
};

struct push_notification_driver {
    const char *name;
    struct push_notification_driver_vfuncs v;
};

struct push_notification_driver_config {
    HASH_TABLE_TYPE(push_notification_config) config;
    const char *raw_config;
};

struct push_notification_driver_user {
    const struct push_notification_driver *driver;
    void *context;
};

struct push_notification_driver_txn {
    const struct push_notification_driver_user *duser;
    struct push_notification_txn *ptxn;

    /* Transaction context. */
    void *context;
};

struct push_notification_driver_list {
    ARRAY(struct push_notification_driver_user *) drivers;
};

struct push_notification_user {
    union mail_user_module_context module_ctx;
    struct push_notification_driver_list *driverlist;
};

struct push_notification_trigger_ctx {
    const char *name;
    void *context;
};

struct push_notification_txn {
    pool_t pool;

    struct mailbox *mbox;
    struct mail_user *muser;
    struct push_notification_user *puser;
    bool initialized;

    enum push_notification_event_trigger trigger;
    struct push_notification_trigger_ctx *trigger_ctx;
    ARRAY(struct push_notification_driver_txn *) drivers;
    ARRAY(struct push_notification_event_config *) events;

    struct event *event;

    /* Used with mailbox events. */
    struct push_notification_txn_mbox *mbox_txn;

    /* Used with mailbox events. */
    HASH_TABLE_TYPE(push_notification_msgs) messages;

    /* Private (used with message events). */
    struct mailbox_transaction_context *t;
};


int
push_notification_driver_init(struct mail_user *user, const char *config_in,
                              pool_t pool,
                              struct push_notification_driver_user **duser_r);
void push_notification_driver_cleanup_all(void);

void ATTR_FORMAT(3, 4)
push_notification_driver_debug(const char *label, struct mail_user *user,
                               const char *fmt, ...);

void push_notification_driver_register
(const struct push_notification_driver *driver);
void push_notification_driver_unregister
(const struct push_notification_driver *driver);


#endif /* PUSH_NOTIFICATION_DRIVERS_H */
