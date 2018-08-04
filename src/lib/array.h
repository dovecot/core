#ifndef ARRAY_H
#define ARRAY_H

/* Array is a buffer accessible using fixed size elements. As long as the
   compiler provides a typeof() operator, the array provides type safety. If
   a wrong type is tried to be added to the array, or if the array's contents
   are tried to be used using a wrong type, the compiler will give a warning.

   Example usage:

   struct foo {
	ARRAY(struct bar) bars;
	...
   };

   i_array_init(&foo->bars, 10);

   struct bar *bar = array_idx(&foo->bars, 5);
   struct baz *baz = array_idx(&foo->bars, 5); // compiler warning

   If you want to pass an array as a parameter to a function, you'll need to
   create a type for the array using ARRAY_DEFINE_TYPE() and use the type in
   the parameter using ARRAY_TYPE(). Any arrays that you want to be passing
   around, such as structure members as in the above example, must also be
   defined using ARRAY_TYPE() too, rather than ARRAY().

   Example:

   ARRAY_DEFINE_TYPE(foo, struct foo);
   void do_foo(ARRAY_TYPE(foo) *foos) {
	struct foo *foo = array_idx(foos, 0);
   }
   struct foo_manager {
        ARRAY_TYPE(foo) foos; // pedantically, ARRAY(struct foo) is a different type
   };
   // ...
        do_foo(&my_foo_manager->foos); // No compiler warning about mismatched types

*/
#include "array-decl.h"
#include "buffer.h"

#define p_array_init(array, pool, init_count) \
	array_create(array, pool, sizeof(**(array)->v), init_count)
#define i_array_init(array, init_count) \
	p_array_init(array, default_pool, init_count)
#define t_array_init(array, init_count) \
	p_array_init(array, pool_datastack_create(), init_count)

#ifdef HAVE_TYPEOF
#  define ARRAY_TYPE_CAST_CONST(array) \
	(typeof(*(array)->v))
#  define ARRAY_TYPE_CAST_MODIFIABLE(array) \
	(typeof(*(array)->v_modifiable))
#  define ARRAY_TYPE_CHECK(array, data) \
	COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE( \
		**(array)->v_modifiable, *(data))
#  define ARRAY_TYPES_CHECK(array1, array2) \
	COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE( \
		**(array1)->v_modifiable, **(array2)->v_modifiable)

#else
#  define ARRAY_TYPE_CAST_CONST(array)
#  define ARRAY_TYPE_CAST_MODIFIABLE(array)
#  define ARRAY_TYPE_CHECK(array, data) 0
#  define ARRAY_TYPES_CHECK(array1, array2) 0
#endif

/* Usage:
   ARRAY(struct foo) foo_arr;
   struct foo *foo;

   array_foreach(&foo_arr, foo) {
     ..
   }

   Note that deleting an element while iterating will cause the iteration to
   skip over the next element. So deleting a single element and breaking out
   of the loop is fine, but continuing the loop is likely a bug. Use
   array_foreach_reverse() instead when deleting multiple elements.
*/
#define array_foreach(array, elem) \
	for (const void *elem ## __foreach_end = \
		(const char *)(elem = *(array)->v) + (array)->arr.buffer->used; \
	     elem != elem ## __foreach_end; (elem)++)
#define array_foreach_modifiable(array, elem) \
	for (const void *elem ## _end = \
		(const char *)(elem = ARRAY_TYPE_CAST_MODIFIABLE(array) \
			buffer_get_modifiable_data((array)->arr.buffer, NULL)) + \
			(array)->arr.buffer->used; \
	     elem != elem ## _end; (elem)++)

/* Iterate the array in reverse order. */
#define array_foreach_reverse(array, elem) \
	for (elem = CONST_PTR_OFFSET(*(array)->v, (array)->arr.buffer->used); \
	     (const char *)(elem--) > (const char *)*(array)->v; )
#define array_foreach_reverse_modifiable(array, elem) \
	for (elem = ARRAY_TYPE_CAST_MODIFIABLE(array) \
		((char *)buffer_get_modifiable_data((array)->arr.buffer, NULL) + \
		 (array)->arr.buffer->used); \
	     (const char *)(elem--) > (const char *)*(array)->v; )

/* Usage:
   ARRAY(struct foo *) foo_ptrs_arr;
   struct foo *foo;

   array_foreach_elem(&foo_ptrs_arr, foo) {
     ..
   } */
#define array_foreach_elem(array, elem) \
	for (const void *_foreach_end = \
		CONST_PTR_OFFSET(*(array)->v, (array)->arr.buffer->used), \
	     *_foreach_ptr = CONST_PTR_OFFSET(*(array)->v, ARRAY_TYPE_CHECK(array, &elem) + \
		COMPILE_ERROR_IF_TRUE(sizeof(elem) > sizeof(void *))) \
		     ;							\
	     (_foreach_ptr != _foreach_end &&		\
	     (memcpy(&elem, _foreach_ptr, sizeof(elem)), TRUE)) \
		;							\
	     _foreach_ptr = CONST_PTR_OFFSET(_foreach_ptr, sizeof(elem)))


#define array_ptr_to_idx(array, elem) \
	((elem) - (array)->v[0])
/* Return index of iterated element inside array_foreach() or
   array_foreach_modifiable() loop. Note that this doesn't work inside
   array_foreach_elem() loop. */
#define array_foreach_idx(array, elem) \
	array_ptr_to_idx(array, elem)

static inline void
array_create_from_buffer_i(struct array *array, buffer_t *buffer,
			   size_t element_size)
{
	array->buffer = buffer;
	array->element_size = element_size;
}
#define array_create_from_buffer(array, buffer, element_size) \
	array_create_from_buffer_i(&(array)->arr, buffer, element_size)

static inline void
array_create_i(struct array *array, pool_t pool,
	       size_t element_size, unsigned int init_count)
{
	buffer_t *buffer;

	buffer = buffer_create_dynamic_max(pool, init_count * element_size,
		SIZE_MAX / element_size < UINT_MAX ? SIZE_MAX :
		UINT_MAX * element_size);
	array_create_from_buffer_i(array, buffer, element_size);
}
#define array_create(array, pool, element_size, init_count) \
	array_create_i(&(array)->arr, pool, element_size, init_count)

static inline void
array_free_i(struct array *array)
{
	buffer_free(&array->buffer);
}
#define array_free(array) \
	array_free_i(&(array)->arr)

static inline void * ATTR_WARN_UNUSED_RESULT
array_free_without_data_i(struct array *array)
{
	return buffer_free_without_data(&array->buffer);
}
#define array_free_without_data(array) \
	ARRAY_TYPE_CAST_MODIFIABLE(array)array_free_without_data_i(&(array)->arr)

static inline bool
array_is_created_i(const struct array *array)
{
	return array->buffer != NULL;
}
#define array_is_created(array) \
	array_is_created_i(&(array)->arr)

static inline pool_t ATTR_PURE
array_get_pool_i(struct array *array)
{
	return buffer_get_pool(array->buffer);
}
#define array_get_pool(array) \
	array_get_pool_i(&(array)->arr)

static inline void
array_clear_i(struct array *array)
{
	buffer_set_used_size(array->buffer, 0);
}
#define array_clear(array) \
	array_clear_i(&(array)->arr)

static inline unsigned int ATTR_PURE
array_count_i(const struct array *array)
{
	return array->buffer->used / array->element_size;
}
#define array_count(array) \
	array_count_i(&(array)->arr)
/* No need for the real count if all we're doing is comparing against 0 */
#define array_is_empty(array) \
	((array)->arr.buffer->used == 0)
#define array_not_empty(array) \
	((array)->arr.buffer->used > 0)

static inline void
array_append_i(struct array *array, const void *data, unsigned int count)
{
	buffer_append(array->buffer, data, count * array->element_size);
}

#define array_append(array, data, count) \
	TYPE_CHECKS(void, ARRAY_TYPE_CHECK(array, data), \
	array_append_i(&(array)->arr, data, count))

static inline void
array_append_array_i(struct array *dest_array, const struct array *src_array)
{
	i_assert(dest_array->element_size == src_array->element_size);
	buffer_append_buf(dest_array->buffer, src_array->buffer, 0, SIZE_MAX);
}
#define array_append_array(dest_array, src_array) \
	TYPE_CHECKS(void, ARRAY_TYPES_CHECK(dest_array, src_array), \
	array_append_array_i(&(dest_array)->arr, &(src_array)->arr))

static inline void
array_insert_i(struct array *array, unsigned int idx,
	       const void *data, unsigned int count)
{
	buffer_insert(array->buffer, idx * array->element_size,
		      data, count * array->element_size);
}

#define array_insert(array, idx, data, count) \
	TYPE_CHECKS(void, ARRAY_TYPE_CHECK(array, data), \
	array_insert_i(&(array)->arr, idx, data, count))

static inline void
array_delete_i(struct array *array, unsigned int idx, unsigned int count)
{
	buffer_delete(array->buffer, idx * array->element_size,
		      count * array->element_size);
}
#define array_delete(array, idx, count) \
	array_delete_i(&(array)->arr, idx, count)

static inline const void *
array_get_i(const struct array *array, unsigned int *count_r)
{
	*count_r = array_count_i(array);
	return array->buffer->data;
}
#define array_get(array, count) \
	ARRAY_TYPE_CAST_CONST(array)array_get_i(&(array)->arr, count)

static inline void *
array_get_copy_i(const struct array *array, pool_t pool, unsigned int *count_r)
{
	*count_r = array_count_i(array);
	if (array->buffer->used == 0)
		return NULL;
	return p_memdup(pool, array->buffer->data, array->buffer->used);
}
#define array_get_copy(array, pool, count) \
	ARRAY_TYPE_CAST_MODIFIABLE(array) \
		array_get_copy_i(&(array)->arr, pool, count)

/* Re: i_assert() vs. pure: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=51971#c1 */
static inline const void * ATTR_PURE
array_idx_i(const struct array *array, unsigned int idx)
{
	i_assert(idx < array->buffer->used / array->element_size);
	return CONST_PTR_OFFSET(array->buffer->data, idx * array->element_size);
}

#define array_front(array) array_idx(array, 0)
#define array_front_modifiable(array) array_idx_modifiable(array, 0)
#define array_back(array) array_idx(array, array_count(array)-1)
#define array_back_modifiable(array) array_idx_modifiable(array, array_count(array)-1)
#define array_pop_back(array) array_delete(array, array_count(array)-1, 1);
#define array_push_back(array, item) array_append(array, (item), 1)
#define array_pop_front(array) array_delete(array, 0, 1)
#define array_push_front(array, item) array_insert(array, 0, (item), 1)

#define array_idx(array, idx) \
	ARRAY_TYPE_CAST_CONST(array)array_idx_i(&(array)->arr, idx)
/* Using *array_idx() will fail if the compiler doesn't support typeof().
   The same can be done with array_idx_elem() for arrays that have pointers. */
#ifdef HAVE_TYPEOF
#  define array_idx_elem(array, idx) \
	(TRUE ? *array_idx(array, idx) : \
		COMPILE_ERROR_IF_TRUE(sizeof(**(array)->v) != sizeof(void *)))
#else
#  define array_idx_elem(array, idx) \
	(*(void **)array_idx_i(&(array)->arr, idx))
#endif

static inline void *
array_get_modifiable_i(struct array *array, unsigned int *count_r)
{
	*count_r = array_count_i(array);
	return buffer_get_modifiable_data(array->buffer, NULL);
}
#define array_get_modifiable(array, count) \
	ARRAY_TYPE_CAST_MODIFIABLE(array) \
		array_get_modifiable_i(&(array)->arr, count)

void *
array_idx_modifiable_i(const struct array *array, unsigned int idx) ATTR_PURE;
#define array_idx_modifiable(array, idx) \
	ARRAY_TYPE_CAST_MODIFIABLE(array) \
		array_idx_modifiable_i(&(array)->arr, idx)

void *array_idx_get_space_i(struct array *array, unsigned int idx);
#define array_idx_get_space(array, idx) \
	ARRAY_TYPE_CAST_MODIFIABLE(array) \
		array_idx_get_space_i(&(array)->arr, idx)

void array_idx_set_i(struct array *array, unsigned int idx, const void *data);
#define array_idx_set(array, idx, data) \
	TYPE_CHECKS(void, ARRAY_TYPE_CHECK(array, data), \
	array_idx_set_i(&(array)->arr, idx, data))

void array_idx_clear_i(struct array *array, unsigned int idx);
#define array_idx_clear(array, idx) \
	array_idx_clear_i(&(array)->arr, idx)

static inline void *
array_append_space_i(struct array *array)
{
	void *data;

	data = buffer_append_space_unsafe(array->buffer, array->element_size);
	memset(data, 0, array->element_size);
	return data;
}
#define array_append_space(array) \
	ARRAY_TYPE_CAST_MODIFIABLE(array)array_append_space_i(&(array)->arr)
#define array_append_zero(array) \
	(void)array_append_space_i(&(array)->arr)

void *array_insert_space_i(struct array *array, unsigned int idx);
#define array_insert_space(array, idx) \
	ARRAY_TYPE_CAST_MODIFIABLE(array) \
		array_insert_space_i(&(array)->arr, idx)

static inline void
array_copy(struct array *dest, unsigned int dest_idx,
	   const struct array *src, unsigned int src_idx, unsigned int count)
{
	i_assert(dest->element_size == src->element_size);

	buffer_copy(dest->buffer, dest_idx * dest->element_size,
		    src->buffer, src_idx * src->element_size,
		    count * dest->element_size);
}

bool array_cmp_i(const struct array *array1,
		 const struct array *array2) ATTR_PURE;
#define array_cmp(array1, array2) \
	array_cmp_i(&(array1)->arr, &(array2)->arr)

/* Test equality via a comparator */
bool array_equal_fn_i(const struct array *array1,
		      const struct array *array2,
		      int (*cmp)(const void*, const void *)) ATTR_PURE;
#define array_equal_fn(array1, array2, cmp) \
	TYPE_CHECKS(bool, \
	ARRAY_TYPES_CHECK(array1, array2) || \
	CALLBACK_TYPECHECK(cmp, int (*)(typeof(*(array1)->v), \
					typeof(*(array2)->v))), \
	array_equal_fn_i(&(array1)->arr, &(array2)->arr, \
			 (int (*)(const void *, const void *))cmp))
bool array_equal_fn_ctx_i(const struct array *array1,
			  const struct array *array2,
			  int (*cmp)(const void*, const void *, const void *),
			  const void *context) ATTR_PURE;
/* Same, but with a context pointer.
   context can't be void* as ``const typeof(context)'' won't compile,
   so ``const typeof(*context)*'' is required instead, and that requires a
   complete type. */
#define array_equal_fn_ctx(array1, array2, cmp, ctx) \
	TYPE_CHECKS(bool, \
	ARRAY_TYPES_CHECK(array1, array2) || \
	CALLBACK_TYPECHECK(cmp, int (*)(typeof(*(array1)->v), \
					typeof(*(array2)->v), \
					const typeof(*ctx)*)), \
	array_equal_fn_ctx_i(&(array1)->arr, &(array2)->arr, \
		(int (*)(const void *, const void *, const void *))cmp, ctx))

void array_reverse_i(struct array *array);
#define array_reverse(array) \
	array_reverse_i(&(array)->arr)

void array_sort_i(struct array *array, int (*cmp)(const void *, const void *));
#define array_sort(array, cmp) \
	TYPE_CHECKS(void, \
	CALLBACK_TYPECHECK(cmp, int (*)(typeof(*(array)->v), \
					typeof(*(array)->v))), \
	array_sort_i(&(array)->arr, (int (*)(const void *, const void *))cmp))

void *array_bsearch_i(struct array *array, const void *key,
		      int (*cmp)(const void *, const void *));
#define array_bsearch(array, key, cmp) \
	TYPE_CHECKS(void *, \
	CALLBACK_TYPECHECK(cmp, int (*)(typeof(const typeof(*key) *), \
					typeof(*(array)->v))), \
	ARRAY_TYPE_CAST_MODIFIABLE(array)array_bsearch_i(&(array)->arr, \
		(const void *)key, (int (*)(const void *, const void *))cmp))

/* Returns pointer to first element for which cmp(key,elem)==0, or NULL */
const void *array_lsearch_i(const struct array *array, const void *key,
			    int (*cmp)(const void *, const void *));
static inline void *array_lsearch_modifiable_i(struct array *array, const void *key,
					       int (*cmp)(const void *, const void *))
{
	return (void *)array_lsearch_i(array, key, cmp);
}
#define ARRAY_LSEARCH_CALL(modifiable, array, key, cmp) \
	TYPE_CHECKS(void *, \
	CALLBACK_TYPECHECK(cmp, int (*)(typeof(const typeof(*key) *), \
					typeof(*(array)->v))), \
	array_lsearch##modifiable##i( \
		&(array)->arr, (const void *)key, \
		(int (*)(const void *, const void *))cmp))
#define array_lsearch(array, key, cmp)					\
	ARRAY_TYPE_CAST_CONST(array)ARRAY_LSEARCH_CALL(_, array, key, cmp)
#define array_lsearch_modifiable(array, key, cmp)			\
	ARRAY_TYPE_CAST_MODIFIABLE(array)ARRAY_LSEARCH_CALL(_modifiable_, array, key, cmp)

#endif
