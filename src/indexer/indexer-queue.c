/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "hash.h"
#include "wildcard-match.h"
#include "indexer-queue.h"

struct indexer_queue {
	indexer_queue_callback_t *callback;
	void (*listen_callback)(struct indexer_queue *);

	/* username+mailbox -> indexer_request */
	HASH_TABLE(struct indexer_request *, struct indexer_request *) requests;
	/* username -> indexer_request */
	HASH_TABLE(char *, struct indexer_request *) users;
	struct indexer_request *head, *tail;
};

struct indexer_queue_iter {
	struct indexer_queue *queue;
	struct hash_iterate_context *hash_iter;
	struct indexer_request *next;
	bool only_working;
};

static unsigned int
indexer_request_hash(const struct indexer_request *request)
{
	return str_hash(request->username) ^ str_hash(request->mailbox);
}

static int indexer_request_cmp(const struct indexer_request *r1,
			       const struct indexer_request *r2)
{
	return strcmp(r1->username, r2->username) == 0 &&
		strcmp(r1->mailbox, r2->mailbox) == 0 ? 0 : 1;
}

struct indexer_queue *
indexer_queue_init(indexer_queue_callback_t *callback)
{
	struct indexer_queue *queue;

	queue = i_new(struct indexer_queue, 1);
	queue->callback = callback;
	hash_table_create(&queue->requests, default_pool, 0,
			  indexer_request_hash, indexer_request_cmp);
	hash_table_create(&queue->users, default_pool, 0, str_hash, strcmp);
	return queue;
}

void indexer_queue_deinit(struct indexer_queue **_queue)
{
	struct indexer_queue *queue = *_queue;

	*_queue = NULL;

	i_assert(indexer_queue_is_empty(queue));
	i_assert(hash_table_count(queue->requests) == 0);
	i_assert(hash_table_count(queue->users) == 0);

	hash_table_destroy(&queue->users);
	hash_table_destroy(&queue->requests);
	i_free(queue);
}

void indexer_queue_set_listen_callback(struct indexer_queue *queue,
				       void (*callback)(struct indexer_queue *))
{
	queue->listen_callback = callback;
}

static struct indexer_request *
indexer_queue_lookup(struct indexer_queue *queue,
		     const char *username, const char *mailbox)
{
	struct indexer_request lookup_request;

	lookup_request.username = (void *)username;
	lookup_request.mailbox = (void *)mailbox;
	return hash_table_lookup(queue->requests, &lookup_request);
}

static void request_add_context(struct indexer_request *request, void *context)
{
	if (context == NULL)
		return;

	if (!array_is_created(&request->contexts))
		i_array_init(&request->contexts, 2);
	array_push_back(&request->contexts, &context);
}

static struct indexer_request *
indexer_queue_append_request(struct indexer_queue *queue, bool append,
			     const char *username, const char *mailbox,
			     const char *session_id,
			     unsigned int max_recent_msgs, void *context)
{
	struct indexer_request *request, *first_request;
	char *first_username;

	request = indexer_queue_lookup(queue, username, mailbox);
	if (request != NULL) {
		if (request->max_recent_msgs > max_recent_msgs)
			request->max_recent_msgs = max_recent_msgs;
		request_add_context(request, context);
		if (request->working) {
			/* we're already indexing this mailbox. */
			if (append)
				request->reindex_tail = TRUE;
			else
				request->reindex_head = TRUE;
		} else {
			if (append) {
				/* keep the request in its old position */
			} else {
				/* move request to beginning of the queue */
				DLLIST2_REMOVE(&queue->head, &queue->tail, request);
				DLLIST2_PREPEND(&queue->head, &queue->tail, request);
			}
		}
		return request;
	}

	request = i_new(struct indexer_request, 1);
	request->username = i_strdup(username);
	request->mailbox = i_strdup(mailbox);
	request->session_id = i_strdup(session_id);
	request->max_recent_msgs = max_recent_msgs;
	request_add_context(request, context);
	hash_table_insert(queue->requests, request, request);

	if (!hash_table_lookup_full(queue->users, username,
				    &first_username, &first_request)) {
		first_username = i_strdup(username);
		hash_table_insert(queue->users, first_username, request);
	} else {
		DLLIST_PREPEND_FULL(&first_request, request,
				    user_prev, user_next);
		hash_table_update(queue->users, first_username, request);
	}

	if (append)
		DLLIST2_APPEND(&queue->head, &queue->tail, request);
	else
		DLLIST2_PREPEND(&queue->head, &queue->tail, request);
	return request;
}

static void indexer_queue_append_finish(struct indexer_queue *queue)
{
	if (queue->listen_callback != NULL)
		queue->listen_callback(queue);
	indexer_refresh_proctitle();
}

void indexer_queue_append(struct indexer_queue *queue, bool append,
			  const char *username, const char *mailbox,
			  const char *session_id, unsigned int max_recent_msgs,
			  void *context)
{
	struct indexer_request *request;

	request = indexer_queue_append_request(queue, append, username, mailbox,
					       session_id, max_recent_msgs,
					       context);
	request->type = INDEXER_REQUEST_TYPE_INDEX;
	indexer_queue_append_finish(queue);
}

void indexer_queue_append_optimize(struct indexer_queue *queue,
				   const char *username, const char *mailbox,
				   void *context)
{
	struct indexer_request *request;

	request = indexer_queue_append_request(queue, TRUE, username, mailbox,
					       NULL, 0, context);
	request->type = INDEXER_REQUEST_TYPE_OPTIMIZE;
	indexer_queue_append_finish(queue);
}

struct indexer_request *indexer_queue_request_peek(struct indexer_queue *queue)
{
	return queue->head;
}

void indexer_queue_request_remove(struct indexer_queue *queue)
{
	struct indexer_request *request = queue->head;

	i_assert(request != NULL);

	DLLIST2_REMOVE(&queue->head, &queue->tail, request);
}

static void indexer_queue_request_status_int(struct indexer_queue *queue,
					     struct indexer_request *request,
					     int percentage)
{
	void *context;
	unsigned int i;

	for (i = 0; i < request->working_context_idx; i++) {
		context = array_idx_elem(&request->contexts, i);
		queue->callback(percentage, context);
	}
}

void indexer_queue_request_status(struct indexer_queue *queue,
				  struct indexer_request *request,
				  int percentage)
{
	i_assert(percentage >= 0 && percentage < 100);

	indexer_queue_request_status_int(queue, request, percentage);
}

void indexer_queue_move_head_to_tail(struct indexer_queue *queue)
{
	struct indexer_request *request = queue->head;

	indexer_queue_request_remove(queue);
	DLLIST2_APPEND(&queue->head, &queue->tail, request);
}

void indexer_queue_request_work(struct indexer_request *request)
{
	request->working = TRUE;
	request->working_context_idx =
		!array_is_created(&request->contexts) ? 0 :
		array_count(&request->contexts);
}

void indexer_queue_request_finish(struct indexer_queue *queue,
				  struct indexer_request **_request,
				  bool success)
{
	struct indexer_request *first_request, *request = *_request;
	char *first_username;

	*_request = NULL;

	indexer_queue_request_status_int(queue, request, success ? 100 : -1);

	if (request->reindex_head || request->reindex_tail) {
		i_assert(request->working);
		request->working = FALSE;
		if (request->working_context_idx > 0) {
			array_delete(&request->contexts, 0,
				     request->working_context_idx);
		}
		if (request->reindex_head)
			DLLIST2_PREPEND(&queue->head, &queue->tail, request);
		else
			DLLIST2_APPEND(&queue->head, &queue->tail, request);
		request->reindex_head = FALSE;
		request->reindex_tail = FALSE;
		return;
	}

	if (!hash_table_lookup_full(queue->users, request->username,
				    &first_username, &first_request))
		i_unreached();
	DLLIST_REMOVE_FULL(&first_request, request, user_prev, user_next);
	if (first_request != NULL)
		hash_table_update(queue->users, first_username, first_request);
	else {
		hash_table_remove(queue->users, first_username);
		i_free(first_username);
	}
	hash_table_remove(queue->requests, request);
	if (array_is_created(&request->contexts))
		array_free(&request->contexts);
	i_free(request->username);
	i_free(request->mailbox);
	i_free(request->session_id);
	i_free(request);

	indexer_refresh_proctitle();
}

static void
indexer_queue_request_cancel(struct indexer_queue *queue,
			     struct indexer_request **_request)
{
	struct indexer_request *request = *_request;

	*_request = NULL;
	request->reindex_head = request->reindex_tail = FALSE;
	DLLIST2_REMOVE(&queue->head, &queue->tail, request);
	indexer_queue_request_finish(queue, &request, FALSE);
}

void indexer_queue_cancel(struct indexer_queue *queue, const char *username,
			  const char *mailbox_mask)
{
	struct indexer_request *request, *next;
	bool single_mailbox =
		mailbox_mask != NULL && wildcard_is_literal(mailbox_mask);

	if (single_mailbox)
		request = indexer_queue_lookup(queue, username, mailbox_mask);
	else
		request = hash_table_lookup(queue->users, username);

	while (request != NULL) {
		next = request->user_next;
		if (mailbox_mask != NULL && !single_mailbox &&
		    !wildcard_match(request->mailbox, mailbox_mask)) {
			/* mailbox mask doesn't match - go to the next one */
		} else if (request->working) {
			/* Can't remove a request that is being worked on,
			   but we can make sure it won't be added back to the
			   queue. */
			request->reindex_head = request->reindex_tail = FALSE;
		} else {
			indexer_queue_request_cancel(queue, &request);
		}
		if (single_mailbox)
			break;
		request = next;
	}
}

void indexer_queue_cancel_all(struct indexer_queue *queue)
{
	struct indexer_request *request;
	struct hash_iterate_context *iter;

	/* remove all reindex-markers so when the current requests finish
	   (or are cancelled) we don't try to retry them (especially during
	   deinit where it crashes) */
	iter = hash_table_iterate_init(queue->requests);
	while (hash_table_iterate(iter, queue->requests, &request, &request))
		request->reindex_head = request->reindex_tail = FALSE;
	hash_table_iterate_deinit(&iter);

	while ((request = indexer_queue_request_peek(queue)) != NULL)
		indexer_queue_request_cancel(queue, &request);
}

bool indexer_queue_is_empty(struct indexer_queue *queue)
{
	return queue->head == NULL;
}

unsigned int indexer_queue_count(struct indexer_queue *queue)
{
	return hash_table_count(queue->requests);
}

struct indexer_queue_iter *
indexer_queue_iter_init(struct indexer_queue *queue, bool only_working)
{
	struct indexer_queue_iter *iter;

	iter = i_new(struct indexer_queue_iter, 1);
	iter->queue = queue;
	iter->only_working = only_working;

	/* First output all the requests currently being worked on. They exist
	   only in the hash table. */
	iter->hash_iter = hash_table_iterate_init(queue->requests);
	return iter;
}

struct indexer_request *indexer_queue_iter_next(struct indexer_queue_iter *iter)
{
	struct indexer_request *request;

	if (iter->hash_iter != NULL) {
		while (hash_table_iterate(iter->hash_iter,
					  iter->queue->requests,
					  &request, &request)) {
			if (request->working)
				return request;
		}
		hash_table_iterate_deinit(&iter->hash_iter);
		if (iter->only_working)
			return NULL;
		iter->next = indexer_queue_request_peek(iter->queue);
	}
	request = iter->next;
	if (request != NULL)
		iter->next = request->next;
	return request;
}

void indexer_queue_iter_deinit(struct indexer_queue_iter **_iter)
{
	struct indexer_queue_iter *iter = *_iter;

	*_iter = NULL;

	hash_table_iterate_deinit(&iter->hash_iter);
	i_free(iter);
}
