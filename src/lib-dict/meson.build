deps = [dep_lib, dep_settings]

lib_dict = static_library(
  'dict',
  'dict.c',
  'dict-redis.c',
  'dict-file.c',
  'dict-fail.c',
  'dict-transaction-memory.c',
  dependencies: deps,
)

dep_dict = declare_dependency(
  link_with: lib_dict,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'dict.h',
  'dict-private.h',
  'dict-transaction-memory.h',
  install_dir: dovecot_includedir,
)

test(
  'dict',
  executable(
    'test-dict',
    'test-dict.c',
    dependencies: [dep_test, dep_dict, dep_lib],
  ),
  suite: 'dict',
)

# TODO: DLUA_WITH_YIELDS - blocked on Lua detection plus ports of src/lib-lua and
# src/lib-doveadm; see the longer note in src/lib-dns-client/meson.build. dict-lua.h and
# dict-lua-private.h are withheld from install_headers above for the same reason.
# dep_dict_lua = declare_dependency(
#   link_with: static_library(
#     'dict-lua',
#     'dict-iter-lua.c',
#     'dict-txn-lua.c',
#     'dict-lua.c',
#     include_directories: ['../lib-lua'],
#     dependencies: [dep_dict, dep_lib, dep_settings],
#   ),
#   include_directories: include_directories('.'),
# )
