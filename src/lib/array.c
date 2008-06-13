/* Copyright (c) 2003-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"

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
		buffer_append_zero(array->buffer, pos - array->buffer->used);
	} else {
		buffer_write_zero(array->buffer, pos, array->element_size);
	}
}

bool array_cmp_i(const struct array *array1, const struct array *array2)
{
	if (!array_is_created_i(array1) || array1->buffer->used == 0)
		return !array_is_created_i(array2) || array2->buffer->used == 0;

	if (!array_is_created_i(array2))
		return FALSE;

	return buffer_cmp(array1->buffer, array2->buffer);
}
