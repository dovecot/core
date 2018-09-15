#ifndef SUBMISSION_BACKEND_RELAY_H
#define SUBMISSION_BACKEND_RELAY_H

#include "submission-backend.h"

struct client;

struct submission_settings;

struct submission_backend *
submission_backend_relay_create(struct client *client,
				const struct submission_settings *set);

#endif
