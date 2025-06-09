/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "dlua-script-private.h"
#include "lua.h"
#include "lauxlib.h"

#define DOVECOT_FILEHANDLE "struct dlua_iostream*"
#define DLUA_DOVECOT_IO "io"
#define MAXARGLINE 250

struct dlua_iostream {
	struct luaL_Stream stream;
	struct istream *is;
	struct ostream *os;
	bool input:1;
};

static int dlua_io_close(lua_State *L)
{
	struct dlua_iostream *stream =
		((struct dlua_iostream*)luaL_checkudata(L, 1, DOVECOT_FILEHANDLE));
	stream->stream.closef = NULL;
	if (stream->input) {
		i_stream_unref(&stream->is);
	} else {
		o_stream_unref(&stream->os);
	}
	return 0;
}

static int dlua_io_gc(lua_State *L)
{
	struct dlua_iostream *stream =
		((struct dlua_iostream*)luaL_checkudata(L, 1, DOVECOT_FILEHANDLE));
	if (stream->stream.closef != NULL)
		dlua_io_close(L);
	i_assert(stream->stream.closef == NULL);
	return 0;
}

static int dlua_io_tostring(lua_State *L)
{
	struct dlua_iostream *stream =
		((struct dlua_iostream*)luaL_checkudata(L, 1, DOVECOT_FILEHANDLE));
	if (stream->stream.closef == NULL)
		lua_pushliteral(L, "file (closed)");
	else if (stream->input)
		lua_pushstring(L, i_stream_get_name(stream->is));
	else
		lua_pushstring(L, o_stream_get_name(stream->os));
	return 1;
}

static int dlua_o_write(lua_State *L)
{
	struct dlua_iostream *stream =
		((struct dlua_iostream*)luaL_checkudata(L, 1, DOVECOT_FILEHANDLE));
	if (stream->stream.closef == NULL)
		return luaL_error(L, "Cannot write to closed file");
	if (stream->input)
		return luaL_error(L, "Cannot write to input stream");

	struct const_iovec vec;
	vec.iov_base = luaL_tolstring(L, 2, &vec.iov_len);
	ssize_t ret = o_stream_sendv(stream->os, &vec, 1);

	if (ret < 0) {
		errno = stream->os->stream_errno;
		return luaL_fileresult(L, 0, o_stream_get_name(stream->os));
	}
	return 0;
}

static int dlua_o_flush(lua_State *L)
{
	struct dlua_iostream *stream =
		((struct dlua_iostream*)luaL_checkudata(L, 1, DOVECOT_FILEHANDLE));
	if (stream->stream.closef == NULL)
		return luaL_error(L, "Cannot flush closed file");
	if (stream->input)
		return luaL_error(L, "Cannot flush input stream");

	ssize_t ret = o_stream_flush(stream->os);

	if (ret < 0) {
		errno = stream->os->stream_errno;
		return luaL_fileresult(L, 0, o_stream_get_name(stream->os));
	}
	return 0;
}

static int dlua_io_setvbuf(lua_State *L)
{
	struct dlua_iostream *stream =
		((struct dlua_iostream*)luaL_checkudata(L, 1, DOVECOT_FILEHANDLE));
	size_t max_size = lua_tonumber(L, 2);

	if (stream->stream.closef == NULL)
		return luaL_error(L, "Cannot change buffer size on closed file");

	if (stream->input)
		i_stream_set_max_buffer_size(stream->is, max_size);
	else
		o_stream_set_max_buffer_size(stream->os, max_size);
	return 0;
}

static bool dlua_read_line(lua_State *L, struct dlua_iostream *stream, bool nl)
{
	/* check available data */
	string_t *str = t_str_new(32);

	/* We don't want to use i_stream_read_next_line() because next call might
	 * be something else, like reading just n bytes from the stream. */
	while (i_stream_have_bytes_left(stream->is)) {
		size_t size;
		const unsigned char *data = i_stream_get_data(stream->is, &size);
		const unsigned char *ptr = memchr(data, '\n', size);

		if (ptr != NULL) {
			ptr++;
			/* check that there is no embedded NUL */
			const unsigned char *ptr2 = memchr(data, '\0', ptr - data);
			if (ptr2 != NULL)
				ptr = ptr2;
			size = ptr - data;
		} else {
			/* stop at first NUL */
			const unsigned char *ptr2 = memchr(data, '\0', size);
			if (ptr2 != NULL) {
				ptr = ptr2;
				size = ptr - data;
			}
		}

		str_append_data(str, data, size);
		/* consume read data from stream */
		i_stream_skip(stream->is, size);

		/* end of read */
		if (ptr != NULL)
			break;

		(void)i_stream_read(stream->is);
	}

	/* Nothing read, fail */
	if (str->used == 0)
		return FALSE;

	/* Check if we want to add or remove newline */
	const char *ptr = strchr(str_c(str), '\n');
	if (ptr == NULL && nl) {
		str_append_c(str, '\n');
	} else if (ptr != NULL && !nl) {
		str_truncate(str, str_len(str) - 1);
	}

	lua_pushstring(L, str_c(str));
	return TRUE;
}

static bool dlua_read_bytes(lua_State *L, struct dlua_iostream *stream, size_t bytes)
{
	size_t size;
	const unsigned char *data;
	string_t *str = t_str_new(32);

	while (bytes > 0 && i_stream_read_more(stream->is, &data, &size) > 0) {
		if (bytes < size)
			size = bytes;
		bytes -= size;
		str_append_data(str, data, size);
		i_stream_skip(stream->is, size);
	}

	lua_pushlstring(L, str->data, str->used);

	return TRUE;
}

/* Adapted from g_read() in lua */
static int dlua_i_read_common(lua_State *L, struct dlua_iostream *stream, int first)
{
	int nargs = lua_gettop(L) - 1;
	bool success;
	int n;

	if (i_stream_read(stream->is) < 0 &&
	    stream->is->stream_errno != 0) {
		/* Skip to error handling. */
		success = FALSE;
	} else if (nargs == 0) {
		success = dlua_read_line(L, stream, TRUE);
		n = first + 1;
	} else {
		luaL_checkstack(L, nargs+LUA_MINSTACK, "too many arguments");
		success = TRUE;
		for (n = first; nargs-- > 0 && success; n++) {
			if (lua_type(L, n) == LUA_TNUMBER) {
				size_t l = (size_t)luaL_checkinteger(L, n);
				success = dlua_read_bytes(L, stream, l);
			} else {
				const char *p = luaL_checkstring(L, n);
				/* skip optional '*' (for compatibility) */
				if (*p == '*')
					p++;
				switch (*p) {
				case 'n':  /* number */
					return luaL_argerror(L, n, "unsupported format");
				case 'l':  /* line */
					success = dlua_read_line(L, stream, FALSE);
					break;
				case 'L':  /* line with end-of-line */
					success = dlua_read_line(L, stream, TRUE);
					break;
				case 'a': /* read entire file */
					success = dlua_read_bytes(L, stream, SIZE_MAX);
					break;
				default:
					return luaL_argerror(L, n, "invalid format");
				}
			}
		}
	}

	if (stream->is->stream_errno != 0) {
		errno = stream->is->stream_errno;
		return luaL_fileresult(L, 0, i_stream_get_name(stream->is));
	}

	if (!success){
		lua_pop(L, 1);
		lua_pushnil(L);
	}

	return n - first;
}

static int dlua_i_read(lua_State *L)
{
	struct dlua_iostream *stream =
		((struct dlua_iostream*)luaL_checkudata(L, 1, DOVECOT_FILEHANDLE));
	if (stream->stream.closef == NULL)
		return luaL_error(L, "Cannot read closed file");
	if (!stream->input)
		return luaL_error(L, "Cannot read from output stream");
	return dlua_i_read_common(L, stream, 2);
}

static int dlua_i_seek(lua_State *L)
{
	static const int mode[] = {SEEK_SET, SEEK_CUR, SEEK_END};
	static const char *const modenames[] = {"set", "cur", "end", NULL};

	struct dlua_iostream *stream =
		((struct dlua_iostream*)luaL_checkudata(L, 1, DOVECOT_FILEHANDLE));
	if (stream->stream.closef == NULL)
		return luaL_error(L, "Cannot seek closed file");
	if (!stream->input)
		return luaL_error(L, "Cannot seek output stream");

	int op = luaL_checkoption(L, 2, "cur", modenames);
	lua_Integer p3 = luaL_optinteger(L, 3, 0);
	off_t offset = (off_t)p3;
	if ((lua_Integer)offset != p3)
		return luaL_argerror(L, 3, "not an integer in proper range");

	if (mode[op] == SEEK_CUR) {
		offset += i_stream_get_absolute_offset(stream->is);
	} else if (mode[op] == SEEK_END) {
		return luaL_argerror(L, 2, "end is not supported");
	}

	i_stream_seek(stream->is, offset);
	return 0;
}

static int dlua_i_readline(lua_State *L)
{
	struct dlua_iostream *stream =
		((struct dlua_iostream*)luaL_checkudata(L, lua_upvalueindex(1), DOVECOT_FILEHANDLE));
	if (stream->stream.closef == NULL)
		return luaL_error(L, "Cannot read closed file");
	if (!stream->input)
		return luaL_error(L, "Cannot read from output stream");

	int i;
	int n = (int)lua_tointeger(L, lua_upvalueindex(2));
	lua_settop(L , 1);
	luaL_checkstack(L, n, "too many arguments");
	for (i = 1; i <= n; i++)  /* push arguments to 'g_read' */
		lua_pushvalue(L, lua_upvalueindex(3 + i));
	n = dlua_i_read_common(L, stream, 2);  /* 'n' is number of results */
	i_assert(n > 0);
	if (lua_toboolean(L, -n))  /* read at least one value? */
		return n;
	if (n > 1) {
		return luaL_error(L, "%s", lua_tostring(L, -n + 1));
	}
	return 0;
}

static int dlua_i_lines(lua_State *L)
{
	int n = lua_gettop(L) - 1;  /* number of arguments to read */
	if (n > MAXARGLINE)
		return luaL_argerror(L, MAXARGLINE + 2, "too many arguments");
	lua_pushinteger(L, n);  /* number of arguments to read */
	lua_pushcclosure(L, dlua_i_readline, 2 + n);
	return 1;
}

static const luaL_Reg dovecot_io_methods[] = {
	{NULL, NULL}
};

static const luaL_Reg flib[] = {
	{"close", dlua_io_close},
	{"flush", dlua_o_flush},
	{"lines", dlua_i_lines},
	{"read", dlua_i_read},
	{"seek", dlua_i_seek},
	{"setvbuf", dlua_io_setvbuf},
	{"write", dlua_o_write},
	{"__gc", dlua_io_gc},
	{"__tostring", dlua_io_tostring},
	{NULL, NULL}
};

void dlua_dovecot_io_register(struct dlua_script *script) {
	dlua_get_dovecot(script->L);
	lua_newtable(script->L);
	luaL_setfuncs(script->L, dovecot_io_methods, 0);
	lua_setfield(script->L, -2, DLUA_DOVECOT_IO);
	lua_pop(script->L, 1);

	luaL_newmetatable(script->L, DOVECOT_FILEHANDLE);  /* create metatable for file handles */
	lua_pushvalue(script->L, -1);  /* push metatable */
	lua_setfield(script->L, -2, "__index");  /* metatable.__index = metatable */
	luaL_setfuncs(script->L, flib, 0);  /* file methods */
	lua_pop(script->L, 1);
};

int dlua_push_istream(struct dlua_script *script, struct istream *is) {
	struct dlua_iostream *stream =
		lua_newuserdata(script->L, sizeof(struct dlua_iostream));
	luaL_setmetatable(script->L, DOVECOT_FILEHANDLE);
	stream->stream.f = NULL;
	stream->stream.closef = dlua_io_close;
	i_stream_ref(is);
	stream->is = is;
	stream->input = TRUE;

	return 1;
};

int dlua_push_ostream(struct dlua_script *script, struct ostream *os) {
	struct dlua_iostream *stream =
		lua_newuserdata(script->L, sizeof(struct dlua_iostream));
	luaL_setmetatable(script->L, DOVECOT_FILEHANDLE);
	stream->stream.f = NULL;
	stream->stream.closef = dlua_io_close;
	o_stream_ref(os);
	stream->os = os;

	return 1;
};

