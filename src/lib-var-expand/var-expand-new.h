#ifndef VAR_EXPAND_NEW_H
#define VAR_EXPAND_NEW_H

/* Used for getting either prefix:key values, or dynamic values for keys
   in value tables.

   Gets key and context, needs to return -1 on error (with error_r set)
   or 0 on success. value_r *must* be non-null on success.

   Prefix is removed before calling the function.
*/
typedef int value_provider_func_t(const char *key, const char **value_r,
				  void *context, const char **error_r);
/* Used for escaping values, gets given string to escape and context,
   must return escaped string. */
typedef const char *var_expand_escape_func_t(const char *str, void *context);

struct var_expand_parser_state;
struct var_expand_program;

#define VAR_EXPAND_TABLE_END { .key = NULL }
#define VAR_EXPAND_CONTEXTS_END (void*)var_expand_contexts_end

struct var_expand_table_new {
	/* Key name, as in %{key} */
	const char *key;
	/* Value to expand into */
	const char *value;
	/* Or function that provides the value */
	value_provider_func_t *func;
};
#define var_expand_table var_expand_table_new

struct var_expand_provider {
	/* key as in %{key:name} */
	const char *key;
	/* function to call to get value */
	value_provider_func_t *func;
};

extern const void *const var_expand_contexts_end;

struct var_expand_params_new {
	/* Variables to use, must end with VAR_EXPAND_TABLE_END,
	   asserts that tables_arr is non-NULL. */
	const struct var_expand_table *table;
	/* Providers to use, must end with VAR_EXPAND_TABLE_END,
	   asserts that providers_arr is non-NULL. */
	const struct var_expand_provider *providers;
	/* Multiple var expand tables, must be NULL terminated */
	const struct var_expand_table *const *tables_arr;
	/* Multiple var expand providers, must be NULL terminated */
	const struct var_expand_provider *const *providers_arr;
	/* Function that gets called to escape values */
	var_expand_escape_func_t *escape_func;
	/* Context for escape function */
	void *escape_context;
	/* Contexts for table functions and providers, can be
	   set to NULL if no multiple contexts are needed, then context
	   is defaulted to.

	   Asserts that contexts ends with VAR_EXPAND_CONTEXTS_END.
	*/
	void *const *contexts;
	/* Context for table functions and providers. */
	void *context;
	/* Event for %{event:} expansion, can be NULL. Global event
	   will be attempted if this is NULL. */
	struct event *event;
};
#define var_expand_params var_expand_params_new

/* Creates a new expansion program for reusing */
int var_expand_program_create(const char *str, struct var_expand_program **program_r,
			      const char **error_r);
/* Lists all seen variables in a program */
const char *const *var_expand_program_variables(const struct var_expand_program *program);
/* Dumps the program into a dest for debugging */
void var_expand_program_dump(const struct var_expand_program *program, string_t *dest);
/* Executes the program with given params. Params can be left NULL, in which case
   empty parameters are used. */
int var_expand_program_execute(string_t *dest, const struct var_expand_program *program,
			       const struct var_expand_params *params,
			       const char **error_r) ATTR_NULL(3);
/* Free up program */
void var_expand_program_free(struct var_expand_program **_program);

/* Creates a new program, executes it and frees it. Params can be left NULL, in which
   case empty parameters are used. */
int var_expand_new(string_t *dest, const char *str, const struct var_expand_params *params,
		   const char **error_r) ATTR_NULL(3);

/* Wrapper for var_expand(), places the result into result_r. */
int t_var_expand(const char *str, const struct var_expand_params *params,
		 const char **result_r, const char **error_r);

/* Merge two tables together, keys in table a will be overwritten with keys
 * from table b in collision. */
struct var_expand_table *
var_expand_merge_tables_new(pool_t pool, const struct var_expand_table *a,
			    const struct var_expand_table *b);

/* Returns true if provider is a built-in provider */
bool var_expand_provider_is_builtin(const char *prefix);

/* Provides size of a table */
static inline size_t ATTR_PURE
var_expand_table_size_new(const struct var_expand_table *table)
{
	size_t n = 0;
	while (table != NULL && table[n].key != NULL)
		 n++;
	return n;
}

/* Get table entry by name. Returns NULL if not found. */
static inline struct var_expand_table *
var_expand_table_get(struct var_expand_table *table, const char *key)
{
	for (size_t i = 0; table[i].key != NULL; i++) {
		if (strcmp(table[i].key, key) == 0) {
			return &(table[i]);
		}
	}
	return NULL;
}

/* Set table variable to value. Asserts that key is found. */
static inline void var_expand_table_set_value(struct var_expand_table *table,
					      const char *key, const char *value,
					      const char *file, unsigned int line)
{
	struct var_expand_table *entry = var_expand_table_get(table, key);
	if (entry != NULL) {
		i_assert(entry->func == NULL);
		entry->value = value;
	} else
		i_panic("%s:%u No key '%s' in table", file, line, key);
}
#define var_expand_table_set_value(table, key, value) \
	var_expand_table_set_value((table), (key), (value), __FILE__, __LINE__);

/* Set table variable function. Asserts that key is found. */
static inline void var_expand_table_set_func(struct var_expand_table *table,
					     const char *key,
					     value_provider_func_t *func,
					     const char *file, unsigned int line)
{
	struct var_expand_table *entry = var_expand_table_get(table, key);
	if (entry != NULL) {
		i_assert(entry->value == NULL);
		entry->func = func;
	} else
		i_panic("%s:%u No key '%s' in table", file, line, key);
}
#define var_expand_table_set_func(table, key, func) \
	var_expand_table_set_func((table), (key), (func), __FILE__, __LINE__);

/* Set key_b variable to key_a. Copies func and value.
   Asserts that both are found. */
static inline void var_expand_table_copy(struct var_expand_table *table,
					 const char *key_b, const char *key_a)
{
	struct var_expand_table *entry_a = var_expand_table_get(table, key_a);
	struct var_expand_table *entry_b = var_expand_table_get(table, key_b);

	i_assert(entry_a != NULL && entry_b != NULL);
	entry_b->value = entry_a->value;
	entry_b->func = entry_a->func;
}

#endif
