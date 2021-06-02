/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "dlua-script-private.h"

#define PCALL_RESUME_STATE "pcall-resume-state"

#define RESUME_TIMEOUT "resume-timeout"
#define RESUME_NARGS "resume-nargs"

struct dlua_pcall_resume_state {
	dlua_pcall_yieldable_callback_t *callback;
	void *context;
	struct timeout *to;
	int status;
};

#ifdef DLUA_WITH_YIELDS
static void call_resume_callback(lua_State *L)
{
	struct dlua_pcall_resume_state *state = dlua_tls_get_ptr(L, PCALL_RESUME_STATE);

	timeout_remove(&state->to);

	dlua_tls_clear(L, PCALL_RESUME_STATE);

	state->callback(L, state->context, state->status);

	i_free(state);
}

static void queue_resume_callback(lua_State *L, int status)
{
	struct dlua_pcall_resume_state *state = dlua_tls_get_ptr(L, PCALL_RESUME_STATE);

	i_assert(status != LUA_YIELD);

	if (status != LUA_OK) {
		int ret;

		/* error occured: run debug.traceback() */

		/* stack: ..., error (top) */
		lua_getglobal(L, "debug");

		/* stack: ..., error, debug table (top) */
		lua_getfield(L, -1, "traceback");

		/* stack: ..., error, debug table, traceback function (top) */
		lua_remove(L, -2);

		/* stack: ..., error, traceback function (top) */
		lua_pushvalue(L, -2); /* duplicate original error */

		/* stack: ..., error, traceback function, error (top) */

		/*
		 * Note that we kept the original error on the stack as well
		 * as passed it to debug.traceback().  The reason for that
		 * is that debug.traceback() itself can fail.  If it fails,
		 * it'll generate its own error - which, ultimately, we
		 * don't care about.  For example, consider the following
		 * function:
		 *
		 * function foo()
		 *   debug.traceback = nil
		 *   error("abc")
		 * end
		 *
		 * If we executed this function, it would error out - but
		 * it'd also cause our pcall to debug.traceback() to fail
		 * with "attempt to call a nil value".  We want to discard
		 * the nil error, and just use the original ("abc").  This
		 * is ok because debug.traceback() simply "improves" the
		 * passed in error message to include a traceback and no
		 * traceback is better than a very mysterious error message.
		 */
		ret = lua_pcall(L, 1, 1, 0);

		/* stack: ..., orig error, traceback result/error (top) */

		if (ret != LUA_OK) {
			/* traceback failed, remove its error */
			lua_remove(L, -1);
		} else {
			/* traceback succeeded, remove original error */
			lua_remove(L, -2);
		}
		/* After traceback has analyzed the stack, drop everything but
		   the error. */
		while (lua_gettop(L) > 1)
			lua_remove(L, -2);
		i_assert(lua_gettop(L) == 1);
	}

	/*
	 * Mangle the passed in status to match dlua_pcall().  Namely, turn
	 * it into -1 on error, and 0+ to indicate the number of return
	 * values.
	 */
	if (status == LUA_OK)
		state->status = lua_gettop(L);
	else
		state->status = -1;

	i_assert(state->to == NULL);
	state->to = timeout_add_short(0, call_resume_callback, L);
}

static void dlua_pcall_yieldable_continue(lua_State *L)
{
	struct timeout *to;
	int nargs, nresults;
	int ret;

	nargs = dlua_tls_get_int(L, RESUME_NARGS);
	to = dlua_tls_get_ptr(L, RESUME_TIMEOUT);

	i_assert(to != NULL);
	timeout_remove(&to);

	dlua_tls_clear(L, RESUME_TIMEOUT);
	dlua_tls_clear(L, RESUME_NARGS);

	ret = lua_resume(L, L, nargs, &nresults);
	if (ret == LUA_YIELD) {
		/*
		 * thread yielded - nothing to do
		 *
		 * We assume something will call lua_resume().  We don't
		 * care if it is a io related callback or just a timeout.
		 */
	} else if (ret == LUA_OK) {
		/* thread completed - invoke callback */
		queue_resume_callback(L, ret);
	} else {
		/* error occurred - invoke callback */
		queue_resume_callback(L, ret);
	}
}

void dlua_pcall_yieldable_resume(lua_State *L, int nargs)
{
	struct timeout *to;

	to = dlua_tls_get_ptr(L, RESUME_TIMEOUT);
	i_assert(to == NULL);

	to = timeout_add_short(0, dlua_pcall_yieldable_continue, L);

	dlua_tls_set_ptr(L, RESUME_TIMEOUT, to);
	dlua_tls_set_int(L, RESUME_NARGS, nargs);
}

/*
 * Call a function with nargs arguments in a way that supports yielding.
 * When the function execution completes, the passed in callback is called.
 *
 * Returns -1 on error or 0 on success.
 */
#undef dlua_pcall_yieldable
int dlua_pcall_yieldable(lua_State *L, const char *func_name, int nargs,
			 dlua_pcall_yieldable_callback_t *callback,
			 void *context, const char **error_r)
{
	struct dlua_pcall_resume_state *state;
	int ret;
	int nresults;

	i_assert(lua_status(L) == LUA_OK);
	i_assert(lua_gettop(L) == nargs);

	lua_getglobal(L, func_name);

	if (!lua_isfunction(L, -1)) {
		/* clean up the stack - function + arguments */
		lua_pop(L, nargs + 1);
		*error_r = t_strdup_printf("'%s' is not a function", func_name);
		return -1;
	}

	/* allocate and stash in TLS callback state */
	state = i_new(struct dlua_pcall_resume_state, 1);
	state->callback = callback;
	state->context = context;

	dlua_tls_set_ptr(L, PCALL_RESUME_STATE, state);

	/* stack: args, func (top) */
	lua_insert(L, -(nargs + 1));

	/* stack: func, args (top) */
	ret = lua_resume(L, L, nargs, &nresults);
	if (ret == LUA_YIELD) {
		/*
		 * thread yielded - nothing to do
		 *
		 * We assume something will call lua_resume().  We don't
		 * care if it is a io related callback or just a timeout.
		 */
	} else {
		/*
		 * thread completed / errored
		 *
		 * Since there is nothing that will come back to this lua
		 * thread, we need to make sure the callback is called.
		 *
		 * We handle errors the same as successful completion in
		 * order to avoid forcing the callers to check for lua
		 * errors in two places - the call here and in the callback.
		 */
		queue_resume_callback(L, ret);
	}

	return 0;
}
#endif
