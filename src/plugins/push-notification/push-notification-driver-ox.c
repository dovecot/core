/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "http-client.h"
#include "http-url.h"
#include "ioloop.h"
#include "istream.h"
#include "settings-parser.h"
#include "json-parser.h"
#include "mailbox-attribute.h"
#include "mail-storage-private.h"
#include "str.h"
#include "strescape.h"
#include "iostream-ssl.h"

#include "push-notification-plugin.h"
#include "push-notification-drivers.h"
#include "push-notification-event-messagenew.h"
#include "push-notification-events.h"
#include "push-notification-txn-msg.h"

#define OX_METADATA_KEY \
    MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER "vendor/vendor.dovecot/http-notify"

/* Default values. */
static const char *const default_events[] = { "MessageNew", NULL };
static const char *const default_mboxes[] = { "INBOX", NULL };
#define DEFAULT_CACHE_LIFETIME_SECS 60
#define DEFAULT_TIMEOUT_MSECS 2000
#define DEFAULT_RETRY_COUNT 1

/* This is data that is shared by all plugin users. */
struct push_notification_driver_ox_global {
    struct http_client *http_client;
    int refcount;
};
static struct push_notification_driver_ox_global *ox_global = NULL;

/* This is data specific to an OX driver. */
struct push_notification_driver_ox_config {
    struct http_url *http_url;
    struct event *event;
    unsigned int cached_ox_metadata_lifetime_secs;
    bool use_unsafe_username;
    unsigned int http_max_retries;
    unsigned int http_timeout_msecs;

    char *cached_ox_metadata;
    time_t cached_ox_metadata_timestamp;
};

/* This is data specific to an OX driver transaction. */
struct push_notification_driver_ox_txn {
    const char *unsafe_user;
};

static void
push_notification_driver_ox_init_global(struct mail_user *user,
	struct push_notification_driver_ox_config *config)
{
    struct http_client_settings http_set;
    struct ssl_iostream_settings ssl_set;

    if (ox_global->http_client == NULL) {
        /* this is going to use the first user's settings, but these are
           unlikely to change between users so it shouldn't matter much. */
        i_zero(&http_set);
        http_set.debug = user->mail_debug;
        http_set.max_attempts = config->http_max_retries+1;
        http_set.request_timeout_msecs = config->http_timeout_msecs;
        http_set.event_parent = user->event;
        i_zero(&ssl_set);
        mail_user_init_ssl_client_settings(user, &ssl_set);
        http_set.ssl = &ssl_set;

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
        *error_r = "Driver requires the url parameter";
        return -1;
    }

    dconfig = p_new(pool, struct push_notification_driver_ox_config, 1);
    dconfig->event = event_create(user->event);
    event_add_category(dconfig->event, &event_category_push_notification);
    event_set_append_log_prefix(dconfig->event, "push-notification-ox: ");

    if (http_url_parse(tmp, NULL, HTTP_URL_ALLOW_USERINFO_PART, pool,
                       &dconfig->http_url, &error) < 0) {
        event_unref(&dconfig->event);
        *error_r = t_strdup_printf("Failed to parse OX REST URL %s: %s",
                                   tmp, error);
        return -1;
    }
    dconfig->use_unsafe_username =
        hash_table_lookup(config->config, (const char *)"user_from_metadata") != NULL;

    e_debug(dconfig->event, "Using URL %s", tmp);

    tmp = hash_table_lookup(config->config, (const char *)"cache_lifetime");
    if (tmp == NULL)
        dconfig->cached_ox_metadata_lifetime_secs = DEFAULT_CACHE_LIFETIME_SECS;
    else if (settings_get_time(tmp, &dconfig->cached_ox_metadata_lifetime_secs, &error) < 0) {
        event_unref(&dconfig->event);
        *error_r = t_strdup_printf("Failed to parse OX cache_lifetime %s: %s",
                                   tmp, error);
        return -1;
    }

    tmp = hash_table_lookup(config->config, (const char *)"max_retries");
    if ((tmp == NULL) ||
        (str_to_uint(tmp, &dconfig->http_max_retries) < 0)) {
        dconfig->http_max_retries = DEFAULT_RETRY_COUNT;
    }
    tmp = hash_table_lookup(config->config, (const char *)"timeout_msecs");
    if ((tmp == NULL) ||
        (str_to_uint(tmp, &dconfig->http_timeout_msecs) < 0)) {
        dconfig->http_timeout_msecs = DEFAULT_TIMEOUT_MSECS;
    }

    e_debug(dconfig->event, "Using cache lifetime: %u",
            dconfig->cached_ox_metadata_lifetime_secs);

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
    struct mail_namespace *ns;
    bool success = FALSE, use_existing_txn = FALSE;
    int ret;

    if ((dconfig->cached_ox_metadata != NULL) &&
        ((dconfig->cached_ox_metadata_timestamp +
          	(time_t)dconfig->cached_ox_metadata_lifetime_secs) > ioloop_time)) {
        return dconfig->cached_ox_metadata;
    }

    /* Get canonical INBOX, where private server-level metadata is stored.
     * See imap/cmd-getmetadata.c */
    if ((dtxn->ptxn->t != NULL) && dtxn->ptxn->mbox->inbox_user) {
        inbox = dtxn->ptxn->mbox;
        use_existing_txn = TRUE;
    } else {
        ns = mail_namespace_find_inbox(dtxn->ptxn->muser->namespaces);
        inbox = mailbox_alloc(ns->list, "INBOX", MAILBOX_FLAG_READONLY);
    }

    ret = mailbox_attribute_get(inbox, MAIL_ATTRIBUTE_TYPE_PRIVATE,
                                    OX_METADATA_KEY, &attr);
    if (ret < 0) {
        e_error(dconfig->event, "Skipped because unable to get attribute: %s",
                mailbox_get_last_internal_error(inbox, NULL));
    } else if (ret == 0) {
        e_debug(dconfig->event,
                "Skipped because not active (/private/"OX_METADATA_KEY" METADATA not set)");
    } else {
        success = TRUE;
    }

    if (!use_existing_txn) {
        mailbox_free(&inbox);
    }
    if (!success)
	    return NULL;

    i_free(dconfig->cached_ox_metadata);
    dconfig->cached_ox_metadata = i_strdup(attr.value);
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
    struct push_notification_driver_ox_config *dconfig = dtxn->duser->context;

    md_value = push_notification_driver_ox_get_metadata(dtxn);
    if (md_value == NULL) {
        return FALSE;
    }

    /* Unused keys: events, expire, folder */
    /* TODO: To be implemented later(?) */
    const char *const *events = default_events;
    time_t expire = INT_MAX;
    const char *const *mboxes = default_mboxes;

    if (expire < ioloop_time) {
        e_debug(dconfig->event, "Skipped due to expiration (%ld < %ld)",
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
        e_debug(dconfig->event, "Skipped because %s is not a watched mailbox",
                mbox_curr);
        return FALSE;
    }

    txn = p_new(dtxn->ptxn->pool, struct push_notification_driver_ox_txn, 1);

    /* Valid keys: user */
    args = t_strsplit_tabescaped(md_value);
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
        e_error(dconfig->event, "No user provided in config");
        return FALSE;
    }

    e_debug(dconfig->event, "User (%s)", txn->unsafe_user);

    for (; *events != NULL; events++) {
        if (strcmp(*events, "MessageNew") == 0) {
            config = p_new(dtxn->ptxn->pool,
                           struct push_notification_event_messagenew_config, 1);
            config->flags = PUSH_NOTIFICATION_MESSAGE_HDR_FROM |
                            PUSH_NOTIFICATION_MESSAGE_HDR_SUBJECT |
                            PUSH_NOTIFICATION_MESSAGE_BODY_SNIPPET;
            push_notification_event_init(dtxn, "MessageNew", config);
            e_debug(dconfig->event, "Handling MessageNew event");
        }
    }

    dtxn->context = txn;

    return TRUE;
}

static void push_notification_driver_ox_http_callback
(const struct http_response *response, struct push_notification_driver_ox_config *dconfig)
{
    switch (response->status / 100) {
    case 2:
        // Success.
        e_debug(dconfig->event, "Notification sent successfully: %s",
	        http_response_get_message(response));
        break;

    default:
        // Error.
        e_error(dconfig->event, "Error when sending notification: %s",
                http_response_get_message(response));
        break;
    }
}

/* Callback needed for i_stream_add_destroy_callback() in
 * push_notification_driver_ox_process_msg. */
static void str_free_i(string_t *str)
{
    str_free(&str);
}

static int push_notification_driver_ox_get_mailbox_status
(struct push_notification_driver_txn *dtxn,
 struct mailbox_status *r_box_status)
{
    struct push_notification_driver_ox_config *dconfig = dtxn->duser->context;
    /* The already opened mailbox. We cannot use or sync it, because we are within a save transaction. */
    struct mailbox *mbox = dtxn->ptxn->mbox;
    struct mailbox *box;
    int ret;

    /* open and sync new instance of the same mailbox to get most recent status */
    box = mailbox_alloc(mailbox_get_namespace(mbox)->list, mailbox_get_name(mbox), MAILBOX_FLAG_READONLY);
    if (mailbox_sync(box, 0) < 0) {
        e_error(dconfig->event, "mailbox_sync(%s) failed: %s", mailbox_get_vname(mbox), mailbox_get_last_internal_error(box, NULL));
        ret = -1;
    } else {
        /* only 'unseen' is needed at the moment */
        mailbox_get_open_status(box, STATUS_UNSEEN, r_box_status);
        e_debug(dconfig->event, "Got status of mailbox '%s': (unseen: %u)",
                mailbox_get_vname(box), r_box_status->unseen);
        ret = 0;
    }

    mailbox_free(&box);
    return ret;
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
    struct mailbox_status box_status;
    bool status_success = TRUE;

    if (push_notification_driver_ox_get_mailbox_status(dtxn, &box_status) < 0) {
        status_success = FALSE;
    }

    messagenew = push_notification_txn_msg_get_eventdata(msg, "MessageNew");
    if (messagenew == NULL) {
        return;
    }

    push_notification_driver_ox_init_global(user, dconfig);

    http_req = http_client_request_url(ox_global->http_client, "PUT",
                                       dconfig->http_url,
                                       push_notification_driver_ox_http_callback,
                                       dconfig);
    http_client_request_set_event(http_req, dconfig->event);
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
        str_append(str, "\"");
    }
    if (messagenew->subject != NULL) {
        str_append(str, ",\"subject\":\"");
        json_append_escaped(str, messagenew->subject);
        str_append(str, "\"");
    }
    if (messagenew->snippet != NULL) {
        str_append(str, ",\"snippet\":\"");
        json_append_escaped(str, messagenew->snippet);
        str_append(str, "\"");
    }
    if (status_success) {
        str_printfa(str, ",\"unseen\":%u", box_status.unseen);
    }
    str_append(str, "}");

    e_debug(dconfig->event, "Sending notification: %s", str_c(str));

    payload = i_stream_create_from_data(str_data(str), str_len(str));
    i_stream_add_destroy_callback(payload, str_free_i, str);
    http_client_request_set_payload(http_req, payload, FALSE);

    http_client_request_submit(http_req);
    i_stream_unref(&payload);
}

static void push_notification_driver_ox_deinit
(struct push_notification_driver_user *duser ATTR_UNUSED)
{
    struct push_notification_driver_ox_config *dconfig = duser->context;

    i_free(dconfig->cached_ox_metadata);
    if (ox_global != NULL) {
        if (ox_global->http_client != NULL)
            http_client_wait(ox_global->http_client);
        i_assert(ox_global->refcount > 0);
        --ox_global->refcount;
    }
    event_unref(&dconfig->event);
}

static void push_notification_driver_ox_cleanup(void)
{
    if ((ox_global != NULL) && (ox_global->refcount <= 0)) {
        if (ox_global->http_client != NULL) {
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
