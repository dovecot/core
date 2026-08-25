deps = [dep_lib]

lib_url = static_library(
  'url',
  'empty.c',
  dependencies: deps,
)

dep_url = declare_dependency(
  link_with: lib_url,
  include_directories: include_directories('.'),
  dependencies: deps,
)
