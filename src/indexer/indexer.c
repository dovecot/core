/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "restrict-access.h"
#include "process-title.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "indexer-client.h"
#include "indexer-queue.h"
#include "worker-connection.h"

static const struct master_service_settings *set;
static struct indexer_queue *queue;

static void
worker_status_callback(int percentage, struct indexer_request *request);
static void worker_avail_callback(void);

void indexer_refresh_proctitle(void)
{
	if (!set->verbose_proctitle)
		return;

	process_title_set(t_strdup_printf("[%u clients, %u requests]",
					  indexer_clients_get_count(),
					  indexer_queue_count(queue)));
}

static bool idle_die(void)
{
	return indexer_queue_is_empty(queue) &&
		worker_connections_get_count() == 0;
}

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);
	indexer_client_create(conn, queue);
}

static bool worker_send_request(struct indexer_request *request)
{
	if (worker_connection_try_create("indexer-worker", request,
					 worker_status_callback,
					 worker_avail_callback) <= 0)
		return FALSE;
	indexer_queue_request_remove(queue);
	indexer_queue_request_work(request);
	return TRUE;
}

static void queue_try_send_more(struct indexer_queue *queue)
{
	struct worker_connection *worker;
	struct indexer_request *request, *first_moved_request = NULL;

	while ((request = indexer_queue_request_peek(queue)) != NULL) {
		worker = worker_connections_find_user(request->username);
		if (worker != NULL) {
			/* There is already a connection handling a request
			 * for this user. Move the request to the back of the
			 * queue and handle requests from other users.
			 * Terminate if we went through all requests. */
			if (request == first_moved_request) {
				/* all requests are waiting for existing users
				   to finish. */
				break;
			}
			if (first_moved_request == NULL)
				first_moved_request = request;
			indexer_queue_move_head_to_tail(queue);
			continue;
		}

		/* create a new connection to a worker */
		if (!worker_send_request(request))
			break;
	}
}

static void queue_listen_callback(struct indexer_queue *queue)
{
	queue_try_send_more(queue);
}

static void
worker_status_callback(int percentage, struct indexer_request *request)
{
	if (percentage >= 0 && percentage < 100) {
		indexer_queue_request_status(queue, request,
					     percentage);
		return;
	}

	indexer_queue_request_finish(queue, &request,
				     percentage == 100);
}

static void worker_avail_callback(void)
{
	/* A new worker became available. Try to shrink the queue. */
	queue_try_send_more(queue);
}

int main(int argc, char *argv[])
{
	const char *error;

	master_service = master_service_init("indexer", 0, &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	if (master_service_settings_read_simple(master_service, NULL,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);
	set = master_service_settings_get(master_service);

	master_service_init_log(master_service);
	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
	master_service_set_idle_die_callback(master_service, idle_die);

	queue = indexer_queue_init(indexer_client_status_callback);
	indexer_queue_set_listen_callback(queue, queue_listen_callback);
	worker_connections_init();
	master_service_init_finish(master_service);

	master_service_run(master_service, client_connected);

	indexer_queue_cancel_all(queue);
	indexer_clients_destroy_all();
	worker_connections_deinit();
	indexer_queue_deinit(&queue);

	master_service_deinit(&master_service);
        return 0;
}
