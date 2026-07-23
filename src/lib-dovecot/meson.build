libdovecot_modules = [
  'auth',
  'auth_client',
  'auth_crypt',
  'charset',
  'dcrypt',
  'dict',
  'dns',
  'dns_client',
  'fs',
  'http',
  'json',
  'lib',
  'login',
  'mail',
  'master',
  'oauth2',
  'program_client',
  'regex',
  'sasl',
  'settings',
  'smtp',
  'ssl_iostream',
  'test',
  'var_expand',
]

libdovecot_libs = []
libdovecot_deps = []

foreach module : libdovecot_modules
  libdovecot_libs += [get_variable(f'lib_@module@')]
  libdovecot_deps += [get_variable(f'dep_@module@')]
endforeach

# Interfaces of the dependencies above: include directories, compile arguments and the
# external libraries they pull in. Deliberately without the static archives - those are
# link_whole'd into libdovecot below. This avoids linking them into every consumer which
# would give any symbol that libdovecot does not export a second private copy.
libdovecot_interface = []
foreach dep : libdovecot_deps
  libdovecot_interface += dep.partial_dependency(
    compile_args: true,
    includes: true,
    link_args: true,
    sources: true,
  )
endforeach

dlib_dovecot = shared_library(
  'dovecot',
  link_whole: libdovecot_libs,
  install: true,
  install_dir: dovecot_pkglibdir,
  version: '0.0.0',
)

dep_dovecot = declare_dependency(
  link_with: dlib_dovecot,
  dependencies: libdovecot_interface,
)

if get_option('default_library') in ['static', 'both']
  static_library(
    'dovecot',
    link_whole: libdovecot_libs,
    install: true,
    install_dir: dovecot_pkglibdir,
  )
endif
