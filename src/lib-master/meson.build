deps = [dep_lib, dep_auth, dep_dns_client, dep_settings, dep_ssl_iostream, dep_var_expand]

lib_master = static_library(
  'master',
  'anvil-client.c',
  'log-error-buffer.c',
  'master-admin-client.c',
  'master-instance.c',
  'master-service.c',
  'master-service-haproxy.c',
  'master-service-settings.c',
  'master-service-ssl.c',
  'stats-client.c',
  'syslog-util.c',
  dependencies: [deps, dir_defines],
)

dep_master = declare_dependency(
  link_with: lib_master,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'anvil-client.h',
  'log-error-buffer.h',
  'master-admin-client.h',
  'master-instance.h',
  'master-interface.h',
  'master-service.h',
  'master-service-private.h',
  'master-service-settings.h',
  'master-service-ssl.h',
  'service-settings.h',
  'stats-client.h',
  'storage-version.h',
  'syslog-util.h',
  install_dir: dovecot_includedir,
)

test_deps = [deps, dep_test, dep_dns, dep_master]

tests = {
  'event-stats': 'test-event-stats.c',
  'service-settings': 'test-master-service-settings.c',
}

foreach test_name, test_src : tests
  test(
    test_name,
    executable(
      import('fs').stem(test_src),
      test_src,
      dependencies: test_deps,
    ),
    suite: 'master',
  )
endforeach
