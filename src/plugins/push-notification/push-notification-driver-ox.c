/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "http-client.h"
#include "http-url.h"
#include "ioloop.h"
#include "istream.h"
#include "json-parser.h"
#include "mailbox-attribute.h"
#include "mail-storage-private.h"
#include "str.h"

#include "push-notification-drivers.h"
#include "push-notification-event-messagenew.h"
#include "push-notification-events.h"
#include "push-notification-txn-msg.h"


#define OX_LOG_LABEL "OX Push Notification: "

#define OX_METADATA_KEY \
    MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER "vendor/vendor.dovecot/http-notify"

/* Default values. */
static const char *const default_events[] = { "MessageNew", NULL };
static const char *const default_mboxes[] = { "INBOX", NULL };
#define DEFAULT_CACHE_LIFETIME 60


/* This is data that is shared by all plugin users. */
struct push_notification_driver_ox_global {
    struct http_client *http_client;
    int refcount;
};
static struct push_notification_driver_ox_global *ox_global = NULL;

/* This is data specific to an OX driver. */
struct push_notification_driver_ox_config {
    struct http_url *http_url;
    const char *cached_ox_metadata;
    unsigned int cached_ox_metadata_lifetime;
    time_t cached_ox_metadata_timestamp;
    bool use_unsafe_username;
};

/* This is data specific to an OX driver transaction. */
struct push_notification_driver_ox_txn {
    const char *unsafe_user;
};

static void
push_notification_driver_ox_init_global(struct mail_user *user)
{
    struct http_client_settings http_set;

    if (ox_global->http_client == NULL) {
        memset(&http_set, 0, sizeof(http_set));
        http_set.debug = user->mail_debug;

        ox_global->http_client = http_client_init(&http_set);
    }
}

static int
push_notification_driver_ox_init(struct push_notification_driver_config *config,
                                 struct mail_user *user, pool_t pool,
                                 void **context, const char **error_r)
{
    struct push_notification_driver_ox_config *dconfig;
    const char *error, *tmp;

    /* Valid config keys: cache_lifetime, url */
    tmp = hash_table_lookup(config->config, (const char *)"url");
    if (tmp == NULL) {
        *error_r = OX_LOG_LABEL "Driver requires the url parameter";
        return -1;
    }

    dconfig = p_new(pool, struct push_notification_driver_ox_config, 1);

    if (http_url_parse(tmp, NULL, HTTP_URL_ALLOW_USERINFO_PART, pool,
                       &dconfig->http_url, &error) < 0) {
        *error_r = t_strdup_printf(OX_LOG_LABEL "Failed to parse OX REST URL %s: %s",
                                   tmp, error);
        return -1;
    }
    dconfig->use_unsafe_username =
        hash_table_lookup(config->config, (const char *)"user_from_metadata") != NULL;

    push_notification_driver_debug(OX_LOG_LABEL, user, "Using URL %s", tmp);

    tmp = hash_table_lookup(config->config, (const char *)"cache_lifetime");
    if ((tmp == NULL) ||
        (str_to_uint(tmp, &dconfig->cached_ox_metadata_lifetime) < 0)) {
        dconfig->cached_ox_metadata_lifetime = DEFAULT_CACHE_LIFETIME;
    }

    push_notification_driver_debug(OX_LOG_LABEL, user,
                                   "Using cache lifetime: %u",
                                   dconfig->cached_ox_metadata_lifetime);

    if (ox_global == NULL) {
        ox_global = i_new(struct push_notification_driver_ox_global, 1);
        ox_global->refcount = 0;
    }

    ++ox_global->refcount;
    *context = dconfig;

    return 0;
}

static const char *push_notification_driver_ox_get_metadata
(struct push_notification_driver_txn *dtxn)
{
    struct push_notification_driver_ox_config *dconfig = dtxn->duser->context;
    struct mail_attribute_value attr;
    struct mailbox *inbox;
    struct mailbox_transaction_context *mctx = NULL;
    struct mail_namespace *ns;
    bool success = FALSE, use_existing_txn = FALSE;
    int ret;

    if ((dconfig->cached_ox_metadata != NULL) &&
        ((dconfig->cached_ox_metadata_timestamp + dconfig->cached_ox_metadata_lifetime) > ioloop_time)) {
        return dconfig->cached_ox_metadata;
    }

    /* Get canonical INBOX, where private server-level metadata is stored.
     * See imap/cmd-getmetadata.c */
    if ((dtxn->ptxn->t != NULL) && dtxn->ptxn->mbox->inbox_user) {
        /* Use the currently open transaction. */
        inbox = dtxn->ptxn->mbox;
        mctx = dtxn->ptxn->t;
        use_existing_txn = TRUE;
    } else {
        ns = mail_namespace_find_inbox(dtxn->ptxn->muser->namespaces);
        inbox = mailbox_alloc(ns->list, "INBOX", MAILBOX_FLAG_READONLY);
        if (mailbox_open(inbox) < 0) {
            i_error(OX_LOG_LABEL "Skipped because unable to open INBOX: %s",
                    mailbox_get_last_error(inbox, NULL));
        } else {
            mctx = mailbox_transaction_begin(inbox, 0);
        }
    }

    if (mctx != NULL) {
        ret = mailbox_attribute_get(mctx, MAIL_ATTRIBUTE_TYPE_PRIVATE,
                                    OX_METADATA_KEY, &attr);
        if (ret < 0) {
            i_error(OX_LOG_LABEL "Skipped because unable to get attribute: %s",
                    mailbox_get_last_error(inbox, NULL));
        } else if (ret == 0) {
            push_notification_driver_debug(OX_LOG_LABEL, dtxn->ptxn->muser,
                                           "Skipped because not active (/private/"OX_METADATA_KEY" METADATA not set)");
        } else {
            success = TRUE;
        }

        if (!use_existing_txn && (mailbox_transaction_commit(&mctx) < 0)) {
            i_error(OX_LOG_LABEL "Transaction commit failed: %s",
                    mailbox_get_last_error(inbox, NULL));
            /* the commit doesn't matter though. */
        }
    }

    if (!use_existing_txn) {
        mailbox_free(&inbox);
    }
    if (!success)
	    return NULL;

    dconfig->cached_ox_metadata =
        p_strdup(dtxn->ptxn->muser->pool, attr.value);
    dconfig->cached_ox_metadata_timestamp = ioloop_time;

    return dconfig->cached_ox_metadata;
}

static bool push_notification_driver_ox_begin_txn
(struct push_notification_driver_txn *dtxn)
{
    const char *const *args;
    struct push_notification_event_messagenew_config *config;
    const char *key, *mbox_curr, *md_value, *value;
    bool mbox_found = FALSE;
    struct push_notification_driver_ox_txn *txn;

    md_value = push_notification_driver_ox_get_metadata(dtxn);
    if (md_value == NULL) {
        return FALSE;
    }
    struct mail_user *user = dtxn->ptxn->muser;

    /* Unused keys: events, expire, folder */
    /* TODO: To be implemented later(?) */
    const char *const *events = default_events;
    time_t expire = INT_MAX;
    const char *const *mboxes = default_mboxes;

    if (expire < ioloop_time) {
        push_notification_driver_debug(OX_LOG_LABEL, user,
                                       "Skipped due to expiration (%ld < %ld)",
                                       (long)expire, (long)ioloop_time);
        return FALSE;
    }

    mbox_curr = mailbox_get_vname(dtxn->ptxn->mbox);
    for (; *mboxes != NULL; mboxes++) {
        if (strcmp(mbox_curr, *mboxes) == 0) {
            mbox_found = TRUE;
            break;
        }
    }

    if (mbox_found == FALSE) {
        push_notification_driver_debug(OX_LOG_LABEL, user,
                                       "Skipped because %s is not a watched mailbox",
                                       mbox_curr);
        return FALSE;
    }

    txn = p_new(dtxn->ptxn->pool, struct push_notification_driver_ox_txn, 1);

    /* Valid keys: user */
    args = t_strsplit_tab(md_value);
    for (; *args != NULL; args++) {
        key = *args;

        value = strchr(key, '=');
        if (value != NULL) {
            key = t_strdup_until(key, value++);
            if (strcmp(key, "user") == 0) {
                txn->unsafe_user = p_strdup(dtxn->ptxn->pool, value);
            }
        }
    }

    if (txn->unsafe_user == NULL) {
        i_error(OX_LOG_LABEL "No user provided in config");
        return FALSE;
    }

    push_notification_driver_debug(OX_LOG_LABEL, user, "User (%s)", txn->unsafe_user);

    for (; *events != NULL; events++) {
        if (strcmp(*events, "MessageNew") == 0) {
            config = p_new(dtxn->ptxn->pool,
                           struct push_notification_event_messagenew_config, 1);
            config->flags = PUSH_NOTIFICATION_MESSAGE_HDR_FROM |
                            PUSH_NOTIFICATION_MESSAGE_HDR_SUBJECT |
                            PUSH_NOTIFICATION_MESSAGE_BODY_SNIPPET;
            push_notification_event_init(dtxn, "MessageNew", config);
            push_notification_driver_debug(OX_LOG_LABEL, user,
                                           "Handling MessageNew event");
        }
    }

    dtxn->context = txn;

    return TRUE;
}

static void push_notification_driver_ox_http_callback
(const struct http_response *response, struct mail_user *user)
{
    switch (response->status / 100) {
    case 2:
        // Success.
	if (user->mail_debug) {
            push_notification_driver_debug(OX_LOG_LABEL, user,
                                           "Notification sent successfully: %u %s",
                                           response->status, response->reason);
	}
        break;

    default:
        // Error.
        i_error(OX_LOG_LABEL "Error when sending notification: %u %s",
                response->status, response->reason);
        break;
    }
}

/* Callback needed for i_stream_add_destroy_callback() in
 * push_notification_driver_ox_process_msg. */
static void str_free_i(string_t *str)
{
    str_free(&str);
}

static void push_notification_driver_ox_process_msg
(struct push_notification_driver_txn *dtxn,
 struct push_notification_txn_msg *msg)
{
    struct push_notification_driver_ox_config *dconfig =
        (struct push_notification_driver_ox_config *)dtxn->duser->context;
    struct http_client_request *http_req;
    struct push_notification_event_messagenew_data *messagenew;
    struct istream *payload;
    string_t *str;
    struct push_notification_driver_ox_txn *txn =
        (struct push_notification_driver_ox_txn *)dtxn->context;
    struct mail_user *user = dtxn->ptxn->muser;

    messagenew = push_notification_txn_msg_get_eventdata(msg, "MessageNew");
    if (messagenew == NULL) {
        return;
    }

    push_notification_driver_ox_init_global(user);

    http_req = http_client_request_url(ox_global->http_client, "PUT",
                                       dconfig->http_url,
                                       push_notification_driver_ox_http_callback,
                                       user);

    http_client_request_add_header(http_req, "Content-Type",
                                   "application/json; charset=utf-8");

    str = str_new(default_pool, 256);
    str_append(str, "{\"user\":\"");
    json_append_escaped(str, dconfig->use_unsafe_username ?
                        txn->unsafe_user : user->username);
    str_append(str, "\",\"event\":\"messageNew\",\"folder\":\"");
    json_append_escaped(str, msg->mailbox);
    str_printfa(str, "\",\"imap-uidvalidity\":%u,\"imap-uid\":%u",
                msg->uid_validity, msg->uid);
    if (messagenew->from != NULL) {
	str_append(str, ",\"from\":\"");
	json_append_escaped(str, messagenew->from);
    }
    if (messagenew->subject != NULL) {
	str_append(str, "\",\"subject\":\"");
	json_append_escaped(str, messagenew->subject);
    }
    if (messagenew->snippet != NULL) {
	str_append(str, "\",\"snippet\":\"");
	json_append_escaped(str, messagenew->snippet);
    }
    str_append(str, "\"}");

    push_notification_driver_debug(OX_LOG_LABEL, user,
                                   "Sending notification: %s", str_c(str));

    payload = i_stream_create_from_data(str_data(str), str_len(str));
    i_stream_add_destroy_callback(payload, str_free_i, str);
    http_client_request_set_payload(http_req, payload, FALSE);

    http_client_request_submit(http_req);
    i_stream_unref(&payload);
}

static void push_notification_driver_ox_deinit
(struct push_notification_driver_user *duser ATTR_UNUSED)
{
    if (ox_global != NULL) {
        i_assert(ox_global->refcount > 0);
        --ox_global->refcount;
    }
}

static void push_notification_driver_ox_cleanup(void)
{
    if ((ox_global != NULL) && (ox_global->refcount <= 0)) {
        if (ox_global->http_client != NULL) {
            http_client_wait(ox_global->http_client);
            http_client_deinit(&ox_global->http_client);
        }
        i_free_and_null(ox_global);
    }
}


/* Driver definition */

extern struct push_notification_driver push_notification_driver_ox;

struct push_notification_driver push_notification_driver_ox = {
    .name = "ox",
    .v = {
        .init = push_notification_driver_ox_init,
        .begin_txn = push_notification_driver_ox_begin_txn,
        .process_msg = push_notification_driver_ox_process_msg,
        .deinit = push_notification_driver_ox_deinit,
        .cleanup = push_notification_driver_ox_cleanup
    }
};
