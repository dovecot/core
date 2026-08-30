#ifndef SUBMISSION_BACKEND_RELAY_H
#define SUBMISSION_BACKEND_RELAY_H

#include "smtp-client-connection.h"
#include "smtp-client-transaction.h"

#include "submission-backend.h"

struct client;
struct submission_backend_relay;

int submission_backend_relay_create(
	struct client *client, struct submission_backend_relay **rbackend_r);

/* Returns the base backend object for this relay backend */
struct submission_backend *
submission_backend_relay_get(struct submission_backend_relay *backend)
	ATTR_PURE;

/* Returns the client connection for this relay backend */
struct smtp_client_connection *
submission_backend_relay_get_connection(
	struct submission_backend_relay *backend) ATTR_PURE;
/* Returns the current client transaction for this relay backend */
struct smtp_client_transaction *
submission_backend_relay_get_transaction(
	struct submission_backend_relay *backend) ATTR_PURE;

/* Initializes the client transaction manually, which allows providing
   alternative transaction flags. */
struct smtp_client_transaction *
submission_backend_relay_init_transaction(
	struct submission_backend_relay *backend,
	enum smtp_client_transaction_flags flags);

#endif
