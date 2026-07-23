fs = import('fs')

var_expand_filenames = [        # Generated source code filenames.
  'var-expand-lexer.c',
  'var-expand-parser.c',
  'var-expand-parser.h',
]
var_expand_files = []           # Generated source code file objects.
var_expand_dir = meson.current_source_dir()

# Check if the generated source code files are already available and create the list of
# source code file objects pointing to them.
foreach filename : var_expand_filenames
  if not fs.is_file(filename)
    # Some or all of the generated source code files are not available. Reset the list of
    # file objects and break out so we can attempt to generate them below.
    var_expand_files = []
    break
  endif
  var_expand_files += files(filename)
endforeach

# A git checkout never ships the generated files, so a copy found here is a leftover from
# an autotools build. Ignore those and force the regeneration of the files.
if var_expand_files.length() != 0 and have_git_tree
  warning('Found var-expand files in the source tree of a git checkout. ' +
          'Going to assume the var-expand files are leftover from autotools')
  var_expand_files = []
endif

if var_expand_files.length() == 0
  # The source files are at least partially unavailable. Attempt to generate them.
  prog_lex = find_program('flex', version: '>=2.6')
  prog_bison = find_program('bison', version: '>=3.6')

  var_expand_files += custom_target(
    'varexpand-lexer',
    input: 'var-expand-lexer.l',
    output: var_expand_filenames[0],
    command: [
      prog_lex,
      '-o', '@OUTPUT@',
      '@INPUT@',
    ],
  )

  var_expand_files += custom_target(
    'varexpand-parser',
    input: 'var-expand-parser.y',
    output: [
      var_expand_filenames[1],
      var_expand_filenames[2],
    ],
    command: [
      prog_bison,
      '--defines=@OUTPUT1@',
      '-o', '@OUTPUT0@',
      '@INPUT@',
    ],
  )

  var_expand_dir = meson.current_build_dir()
endif

# `meson dist` needs to copy the generated source files over from the build directory into
# the source directory in the tarball. This is so a tarball that ships with them can build
# without network access.
meson.add_dist_script(
  generated_dist_script,
  var_expand_dir,          # Where the generated files can be found.
  'src/lib-var-expand',    # Where the generated files should go in the tarball.
  var_expand_filenames,    # The generated source filenames.
)

deps = [dep_lib, dep_regex]

lib_var_expand = static_library(
  'var-expand',
  'expansion-filter.c',
  'expansion-filter-crypt.c',
  'expansion-filter-if.c',
  'expansion-parameter.c',
  'expansion-program.c',
  'expansion-statement.c',
  'var-expand.c',
  'var-expand-split.c',
  var_expand_files,
  dependencies: deps,
)

dep_var_expand = declare_dependency(
  link_with: lib_var_expand,
  include_directories: include_directories('.'),
  dependencies: deps,
)

install_headers(
  'var-expand.h',
  'var-expand-split.h',
  'var-expand-private.h',
  install_dir: dovecot_includedir,
)

test_deps = [
  dep_test,
  dep_lib,
  dep_var_expand,
]

test(
  'var-expand',
  executable(
    'test-var-expand',
    'test-var-expand.c',
    dependencies: test_deps,
  ),
  suite: 'var-expand',
)

if get_option('fuzzing')
  fuzzers = [
    'var-expand',
    'var-expand-import',
  ]

  foreach fuzzer_name : fuzzers
    exe = f'fuzz-@fuzzer_name@'
    src = f'@exe@.c'
    fuzzer = executable(
      exe,
      src,
      link_language: 'cpp',
      pie: true,
      dependencies: [test_deps, ext_fuzzer],
    )

    if fuzzer_test_runs > 0
      test(
        exe,
        fuzzer,
        args: fuzzer_test_args,
        suite: 'var-expand',
        timeout: fuzzer_test_timeout,
        workdir: meson.current_build_dir(),
      )
    endif
  endforeach
endif
