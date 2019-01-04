/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"


void *
array_idx_modifiable_i(const struct array *array, unsigned int idx)
{
	i_assert(idx < array->buffer->used / array->element_size);
	return PTR_OFFSET(array->buffer->data, idx * array->element_size);
}

void *array_idx_get_space_i(struct array *array, unsigned int idx)
{
	return buffer_get_space_unsafe(array->buffer, idx * array->element_size,
				       array->element_size);
}

void array_idx_set_i(struct array *array, unsigned int idx, const void *data)
{
	buffer_write(array->buffer, idx * array->element_size,
		     data, array->element_size);
}

void array_idx_clear_i(struct array *array, unsigned int idx)
{
	buffer_write_zero(array->buffer, idx * array->element_size,
			  array->element_size);
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

bool array_equal_fn_i(const struct array *array1, const struct array *array2,
		      int (*cmp)(const void *, const void*))
{
	unsigned int count1, count2, i;
	size_t size;

	if (!array_is_created_i(array1) || array1->buffer->used == 0)
		return !array_is_created_i(array2) || array2->buffer->used == 0;

	if (!array_is_created_i(array2))
		return FALSE;

	count1 = array_count_i(array1); count2 = array_count_i(array2);
	if (count1 != count2)
		return FALSE;

	size = array1->element_size;
	i_assert(size == array2->element_size);

	for (i = 0; i < count1; i++) {
		if (cmp(CONST_PTR_OFFSET(array1->buffer->data, i * size),
			CONST_PTR_OFFSET(array2->buffer->data, i * size)) != 0)
			return FALSE;
	}
	return TRUE;
}

bool array_equal_fn_ctx_i(const struct array *array1, const struct array *array2,
			  int (*cmp)(const void *, const void *, const void *),
			  const void *context)
{
	unsigned int count1, count2, i;
	size_t size;

	if (!array_is_created_i(array1) || array1->buffer->used == 0)
		return !array_is_created_i(array2) || array2->buffer->used == 0;

	if (!array_is_created_i(array2))
		return FALSE;

	count1 = array_count_i(array1); count2 = array_count_i(array2);
	if (count1 != count2)
		return FALSE;

	size = array1->element_size;
	i_assert(size == array2->element_size);

	for (i = 0; i < count1; i++) {
		if (cmp(CONST_PTR_OFFSET(array1->buffer->data, i * size),
			CONST_PTR_OFFSET(array2->buffer->data, i * size), context) != 0)
			return FALSE;
	}
	return TRUE;
}

void array_reverse_i(struct array *array)
{
	const size_t element_size = array->element_size;
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

	count = array_count_i(array);
	if (count == 0)
		return;
	qsort(buffer_get_modifiable_data(array->buffer, NULL),
	      count, array->element_size, cmp);
}

void *array_bsearch_i(struct array *array, const void *key,
		     int (*cmp)(const void *, const void *))
{
	unsigned int count;

	count = array_count_i(array);
	return bsearch(key, array->buffer->data,
		       count, array->element_size, cmp);
}

const void *array_lsearch_i(const struct array *array, const void *key,
			    int (*cmp)(const void *, const void *))
{
	const void * const data = array->buffer->data;
	const size_t s = array->element_size;
	unsigned int idx;

	for (idx = 0; idx < array_count_i(array); idx++) {
		if (cmp(key, CONST_PTR_OFFSET(data, idx * s)) == 0) {
			return PTR_OFFSET(data, idx * s);
		}
	}

	return NULL;
}
