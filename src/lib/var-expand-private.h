#ifndef VAR_EXPAND_PRIVATE_H
#define VAR_EXPAND_PRIVATE_H 1

struct var_expand_context {
	/* current variables */
	const struct var_expand_table *table;
	/* caller provided function table */
	const struct var_expand_func_table *func_table;
	/* caller provided context */
	void *context;
	/* last offset, negative counts from end*/
	int offset;
	/* last width, negative counts from end */
	int width;
	/* last zero padding */
	bool zero_padding:1;
};

/* this can be used to register a *global* function that is
   prepended to function table. These can be used to register some
   special handling for keys.

   you can call var_expand_with_funcs if you need to
   expand something inside here.

   return -1 on error, 0 on unknown variable, 1 on success
*/
typedef int
var_expand_extension_func_t(struct var_expand_context *ctx,
			    const char *key, const char *field,
			    const char **result_r, const char **error_r);

struct var_expand_extension_func_table {
	const char *key;
	var_expand_extension_func_t *func;
};

int var_expand_long(struct var_expand_context *ctx,
		    const void *key_start, size_t key_len,
		    const char **var_r, const char **error_r);

void var_expand_extensions_init(void);
void var_expand_extensions_deinit(void);

/* Functions registered here are placed before in-built functions,
   so you can include your own implementation of something.
   Be careful. Use NULL terminated list.
*/
void var_expand_register_func_array(const struct var_expand_extension_func_table *funcs);
void var_expand_unregister_func_array(const struct var_expand_extension_func_table *funcs);

#endif
