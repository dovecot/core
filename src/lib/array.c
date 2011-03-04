/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"

#include <stdlib.h>

void *array_idx_modifiable_i(struct array *array, unsigned int idx)
{
	size_t pos;

	pos = idx * array->element_size;
	if (pos >= array->buffer->used) {
		/* index doesn't exist yet, initialize with zero */
		buffer_append_zero(array->buffer, pos + array->element_size -
				   array->buffer->used);
	}
	return buffer_get_space_unsafe(array->buffer, pos, array->element_size);
}

void array_idx_set_i(struct array *array, unsigned int idx, const void *data)
{
	size_t pos;

	pos = idx * array->element_size;
	if (pos > array->buffer->used) {
		/* index doesn't exist yet, initialize with zero */
		buffer_append_zero(array->buffer, pos - array->buffer->used);
	}
	buffer_write(array->buffer, pos, data, array->element_size);
}

void array_idx_clear_i(struct array *array, unsigned int idx)
{
	size_t pos;

	pos = idx * array->element_size;
	if (pos > array->buffer->used) {
		/* index doesn't exist yet, initialize with zero */
		buffer_append_zero(array->buffer, pos - array->buffer->used +
				   array->element_size);
	} else {
		buffer_write_zero(array->buffer, pos, array->element_size);
	}
}

void *array_insert_space_i(struct array *array, unsigned int idx)
{
	void *data;
	size_t pos;

	pos = idx * array->element_size;
	buffer_copy(array->buffer, pos + array->element_size,
		    array->buffer, pos, (size_t)-1);

	data = buffer_get_space_unsafe(array->buffer, pos, array->element_size);
	memset(data, 0, array->element_size);
	return data;
}

bool array_cmp_i(const struct array *array1, const struct array *array2)
{
	if (!array_is_created_i(array1) || array1->buffer->used == 0)
		return !array_is_created_i(array2) || array2->buffer->used == 0;

	if (!array_is_created_i(array2))
		return FALSE;

	return buffer_cmp(array1->buffer, array2->buffer);
}

void array_reverse_i(struct array *array)
{
	const unsigned int element_size = array->element_size;
	unsigned int i, count = array_count_i(array);
	size_t size;
	void *data, *tmp;

	data = buffer_get_modifiable_data(array->buffer, &size);
	tmp = t_buffer_get(array->element_size);
	for (i = 0; i+1 < count; i++, count--) {
		memcpy(tmp, PTR_OFFSET(data, i * element_size), element_size);
		memcpy(PTR_OFFSET(data, i * element_size),
		       PTR_OFFSET(data, (count-1) * element_size),
		       element_size);
		memcpy(PTR_OFFSET(data, (count-1) * element_size), tmp,
		       element_size);
	}
}

void array_sort_i(struct array *array, int (*cmp)(const void *, const void *))
{
	unsigned int count;

	count = array->buffer->used / array->element_size;
	qsort(buffer_get_modifiable_data(array->buffer, NULL),
	      count, array->element_size, cmp);
}

void *array_bsearch_i(struct array *array, const void *key,
		     int (*cmp)(const void *, const void *))
{
	unsigned int count;

	count = array->buffer->used / array->element_size;
	return bsearch(key, array->buffer->data,
		       count, array->element_size, cmp);
}
