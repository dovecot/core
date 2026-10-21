deps = [dep_dovecot, ext_math]

lib_stats_local = static_library(
  'stats-local',
  'client-reader.c',
  'client-writer.c',
  'client-http.c',
  'event-exporter.c',
  'event-exporter-fmt.c',
  'event-exporter-fmt-json.c',
  'event-exporter-fmt-none.c',
  'event-exporter-fmt-tab-text.c',
  'event-exporter-transport-drop.c',
  'event-exporter-transport-http-post.c',
  'event-exporter-transport-log.c',
  'event-exporter-transport-file.c',
  'stats-service-openmetrics.c',
  'stats-service.c',
  'stats-event-category.c',
  'stats-metrics.c',
  'stats-settings.c',
  extra_files: [
    'stats-common.h',
    'client-reader.h',
    'client-writer.h',
    'client-http.h',
    'event-exporter.h',
    'stats-service.h',
    'stats-service-private.h',
    'stats-event-category.h',
    'stats-metrics.h',
    'stats-settings.h',
    'test-stats-common.h',
  ],
  dependencies: deps,
)

executable(
  'stats',
  'main.c',
  link_with: lib_stats_local,
  dependencies: deps,
  install: true,
  install_rpath: dovecot_pkglibdir,
  install_dir: get_option('prefix') / get_option('libexecdir') / 'dovecot',
)

tests = ['stats-metrics', 'client-writer', 'client-reader']

foreach test_name : tests
  exe = f'test-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      'test-stats-common.c',
      link_with: lib_stats_local,
      dependencies: [deps, dep_test],
    ),
    suite: 'stats',
  )
endforeach
