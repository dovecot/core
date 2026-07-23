deps = [dep_lib, dep_settings]

lib_dns_client = static_library(
  'dns-client',
  'dns-client-cache.c',
  'dns-lookup.c',
  'dns-client-settings.c',
  dependencies: [deps, dir_defines],
)

dep_dns_client = declare_dependency(
  link_with: lib_dns_client,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'dns-client-cache.h',
  'dns-lookup.h',
  install_dir: dovecot_includedir,
)

test_deps = [deps, dep_test, dep_dns, dep_dns_client]

test(
  'dns-lookup',
  executable(
    'test-dns-lookup',
    'test-dns-lookup.c',
    dependencies: test_deps,
  ),
  suite: 'dns-client',
)

# TODO: DLUA_WITH_YIELDS - dns-lua.c is not ported yet. See libdns_lua_la in Makefile.am.
# The dns methods yield via lua_yieldk(), so autoconf only sets DLUA_WITH_YIELDS when both
# lua_resume() and lua_yieldk() are present (m4/want_lua.m4). Getting there needs:
#  - Lua detection (HAVE_LUA/BUILTIN_LUA plus the function probes)
#  - A port of src/lib-lua
#  - A port of src/lib-doveadm - libdlua LIBADDs libdoveadm_client_lua under yields.
# Only then can this and lib-dict's commented-out dep_dict_lua be enabled. dns-lua.h is
# withheld from install_headers above for the same reason.
