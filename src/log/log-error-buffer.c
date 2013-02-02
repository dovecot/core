/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "log-error-buffer.h"

#define LOG_ERROR_BUFFER_MAX_LINES 1000

struct log_error_data {
	struct log_error_data *next;

	enum log_type type;
	time_t timestamp;
	unsigned char prefix_text[];
};

struct log_error_buffer {
	struct log_error_data *head, *tail;
	unsigned int count;
};

struct log_error_buffer_iter {
	struct log_error_buffer *buf;
	struct log_error_data *cur;
	struct log_error error;
};

struct log_error_buffer *log_error_buffer_init(void)
{
	struct log_error_buffer *buf;

	buf = i_new(struct log_error_buffer, 1);
	return buf;
}

static void log_error_buffer_delete_head(struct log_error_buffer *buf)
{
	struct log_error_data *data;

	i_assert(buf->head != NULL);

	buf->count--;
	data = buf->head;
	buf->head = data->next;
	if (buf->tail == data) {
		/* last one */
		buf->tail = NULL;
	}
	i_free(data);
}

void log_error_buffer_add(struct log_error_buffer *buf,
			  const struct log_error *error)
{
	unsigned int prefix_size = strlen(error->prefix)+1;
	unsigned int text_size = strlen(error->text)+1;
	struct log_error_data *data;

	if (buf->count == LOG_ERROR_BUFFER_MAX_LINES)
		log_error_buffer_delete_head(buf);

	/* @UNSAFE */
	data = i_malloc(sizeof(*data) + prefix_size + text_size);
	data->type = error->type;
	data->timestamp = error->timestamp;
	memcpy(data->prefix_text, error->prefix, prefix_size);
	memcpy(data->prefix_text + prefix_size, error->text, text_size);

	if (buf->tail != NULL)
		buf->tail->next = data;
	else
		buf->head = data;
	buf->tail = data;
	buf->count++;
}

void log_error_buffer_deinit(struct log_error_buffer **_buf)
{
	struct log_error_buffer *buf = *_buf;

	*_buf = NULL;
	while (buf->count > 0)
		log_error_buffer_delete_head(buf);
	i_free(buf);
}

struct log_error_buffer_iter *
log_error_buffer_iter_init(struct log_error_buffer *buf)
{
	struct log_error_buffer_iter *iter;

	iter = i_new(struct log_error_buffer_iter, 1);
	iter->buf = buf;
	iter->cur = buf->head;
	return iter;
}

struct log_error *
log_error_buffer_iter_next(struct log_error_buffer_iter *iter)
{
	struct log_error_data *data = iter->cur;

	if (data == NULL)
		return NULL;
	iter->cur = iter->cur->next;

	iter->error.type = data->type;
	iter->error.timestamp = data->timestamp;
	iter->error.prefix = (const void *)data->prefix_text;
	iter->error.text = (const void *)(data->prefix_text +
					  strlen(iter->error.prefix) + 1);
	return &iter->error;
}

void log_error_buffer_iter_deinit(struct log_error_buffer_iter **_iter)
{
	struct log_error_buffer_iter *iter = *_iter;

	*_iter = NULL;

	i_free(iter);
}
