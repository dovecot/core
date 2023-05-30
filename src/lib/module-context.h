#ifndef MODULE_CONTEXT_H
#define MODULE_CONTEXT_H

#include "array.h"

/*
   This is a bit complex to use, but it prevents using wrong module IDs
   in module_contexts arrays.

   ---------
   The main structure is implemented like this:

   struct STRUCT_NAME_module_register {
	   unsigned int id;
   };
   union STRUCT_NAME_module_context {
	   struct STRUCT_NAME_module_register *reg;
	   // it's allowed to have some structure here so it won't waste space.
	   // for example: struct STRUCT_NAME_vfuncs super;
   };
   struct STRUCT_NAME {
	ARRAY(union STRUCT_NAME_module_context *) module_contexts;
   };
   extern struct STRUCT_NAME_module_register STRUCT_NAME_module_register;

   ---------
   The usage in modules goes like:

   static MODULE_CONTEXT_DEFINE(mymodule_STRUCT_NAME_module,
				&STRUCT_NAME_module_register);
   struct mymodule_STRUCT_NAME {
	union STRUCT_NAME_module_context module_ctx;
	// module-specific data
   };

   struct mymodule_STRUCT_NAME *ctx = i_new(...);
   MODULE_CONTEXT_SET(obj, mymodule_STRUCT_NAME_module, ctx);

   struct mymodule_STRUCT_NAME *ctx =
	MODULE_CONTEXT(obj, mymodule_STRUCT_NAME_module);
*/

#define OBJ_REGISTER(obj) \
	((**(obj)->module_contexts.v)->reg)
#define OBJ_REGISTER_COMPATIBLE(obj, id_ctx) \
	COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE(OBJ_REGISTER(obj), (id_ctx).reg)

#ifdef HAVE_TYPEOF
#  define MODULE_CONTEXT_DEFINE(_name, _reg) \
	struct _name { \
		struct module_context_id id; \
		typeof(_reg) reg; \
	} _name
#  define MODULE_CONTEXT_INIT(_reg) \
	{ { &(_reg)->id, 0, FALSE }, NULL }
#else
#  define MODULE_CONTEXT_DEFINE(_name, _reg) \
	struct _name { \
		struct module_context_id id; \
	} _name
#  define MODULE_CONTEXT_INIT(_reg) \
	{ { &(_reg)->id, 0, FALSE } }
#endif

#define MODULE_CONTEXT_DEFINE_INIT(_name, _reg) \
	MODULE_CONTEXT_DEFINE(_name, _reg) = MODULE_CONTEXT_INIT(_reg)

struct module_context_id {
	unsigned int *module_id_register;
	unsigned int module_id;
	bool module_id_set;
};

static inline unsigned int module_get_context_id(struct module_context_id *id)
{
	if (!id->module_id_set) {
		id->module_id = *id->module_id_register;
		id->module_id_set = TRUE;
		*id->module_id_register += 1;
	}
	return id->module_id;
}

static inline void *
module_context_get(struct array *array, struct module_context_id *id)
{
	unsigned int module_id = module_get_context_id(id);
	if (module_id >= array_count_i(array))
		return NULL;
	void **ctx = (void **)array_idx_modifiable_i(array, module_id);
	return *ctx;
}
#define MODULE_CONTEXT(obj, id_ctx) \
	(TRUE ? module_context_get(&(obj)->module_contexts.arr, &(id_ctx).id) : \
	OBJ_REGISTER_COMPATIBLE(obj, id_ctx))

static inline void *
module_context_get_require(struct array *array, struct module_context_id *id,
			   const char *panic_message)
{
	void *ctx = module_context_get(array, id);
	if (ctx == NULL)
		i_panic("%s", panic_message);
	return ctx;
}
/* Will crash if context is missing. This is mainly used to simplify code and
   prevent static analyzers from complaining about NULL pointer dereferences. */
#define MODULE_CONTEXT_REQUIRE(obj, id_ctx) \
	(TRUE ? module_context_get_require(&(obj)->module_contexts.arr, \
		&(id_ctx).id, "Module context " #id_ctx " missing") : \
	OBJ_REGISTER_COMPATIBLE(obj, id_ctx))

#define MODULE_CONTEXT_SET_FULL(obj, id_ctx, ctx, module_ctx) STMT_START { \
	(void)COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE(module_ctx, \
			(**(obj)->module_contexts.v)); \
	(void)OBJ_REGISTER_COMPATIBLE(obj, id_ctx); \
	void *_module_tmp = ctx; \
	array_idx_set_i(&(obj)->module_contexts.arr, \
		module_get_context_id(&(id_ctx).id), &_module_tmp); \
	} STMT_END

#define MODULE_CONTEXT_SET(obj, id_ctx, context) \
	MODULE_CONTEXT_SET_FULL(obj, id_ctx, context, &(context)->module_ctx)
#define MODULE_CONTEXT_SET_SELF(obj, id_ctx, context) \
	MODULE_CONTEXT_SET_FULL(obj, id_ctx, context, context)

#define MODULE_CONTEXT_UNSET(obj, id_ctx) \
	array_idx_clear(&(obj)->module_contexts, (id_ctx).id.module_id)

#endif
