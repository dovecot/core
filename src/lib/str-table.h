#ifndef STR_TABLE_H
#define STR_TABLE_H

/* Hash table containing string -> refcount. */

struct str_table *str_table_init(void);
void str_table_deinit(struct str_table **table);

/* Returns TRUE if there are no referenced strings in the table. */
bool str_table_is_empty(struct str_table *table);

/* Return string allocated from the strtable and increase its reference
   count. */
const char *str_table_ref(struct str_table *table, const char *str);
/* Decrease string's reference count, freeing it if it reaches zero.
   The str pointer must have been returned by the str_table_ref(). */
void str_table_unref(struct str_table *table, const char **str);

#endif
