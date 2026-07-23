fs = import('fs')

settings_history_filenames = [        # Generated source code filenames.
  'settings-history-core.h',
]
settings_history_files = []           # Generated source code file objects.
settings_history_dir = meson.current_source_dir()

# Check if the generated source code files are already available and create the list of
# source code file objects pointing to them.
foreach filename : settings_history_filenames
  if not fs.is_file(filename)
    # Some or all of the generated source code files are not available. Reset the list of
    # file objects and break out so we can attempt to generate them below.
    settings_history_files = []
    break
  endif
  settings_history_files += files(filename)
endforeach

# A git checkout never ships the generated files, so a copy found here is a leftover from
# an autotools build. Ignore those and force the regeneration of the files.
if settings_history_files.length() != 0 and have_git_tree
  warning('Found a settings history file in the source tree of a git checkout. ' +
          'Going to assume the settings history file is leftover from autotools')
  settings_history_files = []
endif

if settings_history_files.length() == 0
  # The source files are at least partially unavailable. Attempt to generate them.
  py = import('python')
  python = py.find_installation(
    'python3',
    modules: [
      'argparse',
      'sys',
      'pathlib',
    ],
    required: true,
  )

  settings_history_files += custom_target(
    'settings-history-core',
    command: [
      python,
      '@INPUT0@',
      '--pro', get_option('pro-build').to_int().to_string(),
      '@INPUT1@',
      '@OUTPUT@',
    ],
    input: [
      'settings-history.py',
      'settings-history-core.txt',
    ],
    output: settings_history_filenames[0],
    capture: false,
  )

  settings_history_dir = meson.current_build_dir()
endif

# `meson dist` needs to copy the generated source files over from the build directory into
# the source directory in the tarball. This is so a tarball that ships with them can build
# without network access.
meson.add_dist_script(
  generated_dist_script,
  settings_history_dir,          # Where the generated files can be found.
  'src/lib-settings',            # Where the generated files should go in the tarball.
  settings_history_filenames,    # The generated source filenames.
)

deps = [dep_lib, dep_var_expand, dep_dns]

lib_settings = static_library(
  'settings',
  'settings.c',
  'settings-history.c',
  'settings-parser.c',
  settings_history_files,
  dependencies: deps,
)

dep_settings = declare_dependency(
  link_with: lib_settings,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'settings.h',
  'settings-history.h',
  'settings-parser.h',
  'settings-consts.h',
  install_dir: dovecot_includedir,
)

test_deps = [deps, dep_test, dep_settings]

tests = ['settings', 'settings-parser']

foreach test_name : tests
  exe = f'test-@test_name@'
  src = f'@exe@.c'
  test(
    test_name,
    executable(
      exe,
      src,
      dependencies: test_deps,
    ),
    suite: 'settings',
  )
endforeach
