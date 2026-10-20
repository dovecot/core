anvil = executable(
  'anvil',
  'admin-client.c',
  'anvil-connection.c',
  'connect-limit.c',
  'penalty.c',
  'admin-client-pool.c',
  'anvil-settings.c',
  'main.c',
  extra_files: [
    'admin-client-pool.h',
    'admin-client.h',
    'anvil-connection.h',
    'common.h',
    'connect-limit.h',
    'penalty.h',
  ],
  dependencies: dep_dovecot,
  install: true,
  install_rpath: dovecot_pkglibdir,
  install_dir: get_option('prefix') / get_option('libexecdir') / 'dovecot',
)

tests = [
  {'name': 'connect-limit', 'extra-objects': 'connect-limit.c' },
  {'name': 'penalty',       'extra-objects': 'penalty.c'       },
]

foreach test : tests
  name = test['name']
  exe = f'test-@name@'
  src = f'@exe@.c'
  test(
    name,
    executable(
      exe,
      src,
      objects: anvil.extract_objects(test['extra-objects']),
      dependencies: [dep_test, dep_lib],
    ),
    suite: 'anvil',
  )
endforeach
