deps = [
  dep_lib,
  dep_master,
  dep_dict,
  dep_fs,
  dep_settings,
  dep_var_expand,
]

headers = ['dict-client.h']

lib_dict_extra = static_library(
  'dict-extra',
  'dict-client.c',
  'dict-fs.c',
  'dict-register.c',
  extra_files: headers,
  dependencies: deps,
)

dep_dict_extra = declare_dependency(
  link_with: lib_dict_extra,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(headers, install_dir: dovecot_includedir)

test_deps = [dep_test, dep_dict_extra, dep_ssl_iostream, dep_dns, dep_regex]

test(
  'dict-fs',
  executable(
    'test-dict-fs',
    'test-dict-fs.c',
    dependencies: test_deps,
  ),
  suite: 'dict-extra',
)
