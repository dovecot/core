/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "restrict-access.h"
#include "process-title.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "indexer-client.h"
#include "indexer-queue.h"
#include "worker-pool.h"
#include "worker-connection.h"

struct worker_request {
	struct worker_connection *conn;
	struct indexer_request *request;
};

static const struct master_service_settings *set;
static struct indexer_queue *queue;
static struct worker_pool *worker_pool;
static struct timeout *to_send_more;

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
		!worker_pool_have_busy_connections(worker_pool);
}

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);
	(void)indexer_client_create(conn->fd, queue);
}

static void worker_send_request(struct worker_connection *conn,
				struct indexer_request *request)
{
	struct worker_request *wrequest;

	wrequest = i_new(struct worker_request, 1);
	wrequest->conn = conn;
	wrequest->request = request;

	indexer_queue_request_work(request);
	worker_connection_request(conn, request, wrequest);
}

static void queue_try_send_more(struct indexer_queue *queue)
{
	struct worker_connection *conn;
	struct indexer_request *request;

	timeout_remove(&to_send_more);

	while ((request = indexer_queue_request_peek(queue)) != NULL) {
		conn = worker_pool_find_username_connection(worker_pool,
							    request->username);
		if (conn != NULL) {
			/* there is already a worker handling this user.
			   it must be the one doing the indexing. use the same
			   connection for sending this next request. */
		} else {
			/* try to find an empty worker */
			if (!worker_pool_get_connection(worker_pool, &conn))
				break;
		}
		indexer_queue_request_remove(queue);
		worker_send_request(conn, request);
	}
}

static void queue_listen_callback(struct indexer_queue *queue)
{
	queue_try_send_more(queue);
}

static void worker_status_callback(int percentage, void *context)
{
	struct worker_request *request = context;

	if (percentage >= 0 && percentage < 100) {
		indexer_queue_request_status(queue, request->request,
					     percentage);
		return;
	}

	indexer_queue_request_finish(queue, &request->request,
				     percentage == 100);
	if (worker_pool != NULL) /* not in deinit */
		worker_pool_release_connection(worker_pool, request->conn);
	i_free(request);

	/* if this was the last request for the connection, we can send more
	   through it. delay it a bit, since we may be coming here from
	   worker_connection_disconnect() and we want to finish it up. */
	if (to_send_more == NULL)
		to_send_more = timeout_add_short(0, queue_try_send_more, queue);
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
	worker_pool = worker_pool_init("indexer-worker",
				       worker_status_callback);
	master_service_init_finish(master_service);

	master_service_run(master_service, client_connected);

	indexer_queue_cancel_all(queue);
	indexer_clients_destroy_all();
	worker_pool_deinit(&worker_pool);
	indexer_queue_deinit(&queue);
	timeout_remove(&to_send_more);

	master_service_deinit(&master_service);
        return 0;
}
