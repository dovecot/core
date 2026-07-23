deps = [dep_lib, dep_settings, dep_auth, dep_json, dep_ssl_iostream, dep_oauth2]

client_mechanisms = [
  'dsasl-client-mech-anonymous.c',
  'dsasl-client-mech-cram-md5.c',
  'dsasl-client-mech-digest-md5.c',
  'dsasl-client-mech-external.c',
  'dsasl-client-mech-login.c',
  'dsasl-client-mech-oauthbearer.c',
  'dsasl-client-mech-plain.c',
  'dsasl-client-mech-scram.c',
]

server_mechanisms = [
  'sasl-server-mech-anonymous.c',
  'sasl-server-mech-cram-md5.c',
  'sasl-server-mech-digest-md5.c',
  'sasl-server-mech-external.c',
  'sasl-server-mech-login.c',
  'sasl-server-mech-oauth2.c',
  'sasl-server-mech-plain.c',
  'sasl-server-mech-scram.c',
  'sasl-server-mech-winbind.c',
]

lib_sasl = static_library(
  'sasl',
  'sasl-oauth2.c',
  client_mechanisms,
  'dsasl-client.c',
  server_mechanisms,
  'sasl-server-mech.c',
  'sasl-server-request.c',
  'sasl-server.c',
  dependencies: deps,
)

dep_sasl = declare_dependency(
  link_with: lib_sasl,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'sasl-common.h',
  'sasl-oauth2.h',
  'dsasl-client.h',
  'dsasl-client-private.h',
  'sasl-server.h',
  'sasl-server-gssapi.h',
  'sasl-server-oauth2.h',
  'sasl-server-protected.h',
  'sasl-server-private.h',
  'sasl-server-mech-scram.h',
  install_dir: dovecot_includedir,
)

# TODO: Deliberately without a consumer: the only one is src/lib-dovecot-gssapi, which is
# not ported yet. The archive is still built.
if have_gssapi
  sasl_gssapi_deps = [deps, dep_sasl, dep_auth_gssapi]

  dep_sasl_gssapi = declare_dependency(
    link_with: static_library(
      'sasl-gssapi',
      'dsasl-client-mech-gssapi.c',
      'sasl-server-mech-gssapi.c',
      dependencies: sasl_gssapi_deps,
    ),
    include_directories: include_directories('.'),
    dependencies: sasl_gssapi_deps,
  )
endif

test_deps = [dep_sasl, dep_auth, dep_ssl_iostream, dep_settings, dep_test, dep_lib]

# With GSSAPI the authentication test and fuzzer compile the mechs themselves alongside
# stubbed-out GSSAPI and krb5 libraries, rather than linking the real libsasl-gssapi.
sasl_gssapi_test_sources = []
sasl_gssapi_test_deps = []
if have_gssapi
  sasl_gssapi_test_sources = [
    'gssapi-dummy.c',
    'krb5-dummy.c',
    'dsasl-client-mech-gssapi.c',
    'sasl-server-mech-gssapi.c',
  ]
  sasl_gssapi_test_deps = [dep_auth_gssapi]
endif

tests = ['client', 'oauth2']

foreach test_name : tests
  exe = f'test-sasl-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      dependencies: test_deps,
    ),
    suite: 'sasl',
  )
endforeach

# test-sasl-authentication pulls in an extra NTLM client stub and runs it (its path is
# passed via TEST_WINBIND_HELPER_PATH).
ntlm_dummy = executable(
  'ntlm_dummy',
  'ntlm_dummy.c',
  dependencies: dep_lib,
)

test(
  'authentication',
  executable(
    'test-sasl-authentication',
    'test-sasl-authentication.c',
    'dsasl-client-mech-ntlm-dummy.c',
    sasl_gssapi_test_sources,
    c_args: '-DTEST_WINBIND_HELPER_PATH="@0@"'.format(ntlm_dummy.full_path()),
    dependencies: [test_deps, sasl_gssapi_test_deps],
  ),
  depends: ntlm_dummy,
  suite: 'sasl',
)

if get_option('fuzzing')
  fuzzer = executable(
    'fuzz-sasl-authentication',
    'fuzz-sasl-authentication.c',
    'dsasl-client-mech-ntlm-dummy.c',
    sasl_gssapi_test_sources,
    link_language: 'cpp',
    pie: true,
    dependencies: [test_deps, sasl_gssapi_test_deps, ext_fuzzer],
  )

  if fuzzer_test_runs > 0
    test(
      'fuzz-sasl-authentication',
      fuzzer,
      args: fuzzer_test_args,
      suite: 'sasl',
      timeout: fuzzer_test_timeout,
      workdir: meson.current_build_dir(),
    )
  endif
endif
