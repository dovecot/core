project(
  'dovecot',
  'c',
  default_options: {
    'b_pie': true,
    'c_std': 'gnu11',
    'cpp_std': 'gnu++11',
    'buildtype': 'debugoptimized',
    'warning_level': '2',
    'sysconfdir': 'etc',
    'localstatedir': 'var',
  },
  meson_version: '>=1.4.0',
  version: run_command(
    'build-aux/git-version-gen',
    check: true,
  ).stdout().strip(),
)

add_languages(
  'cpp',
  required: true,
  native: false,
)

# Cross compilation is not supported: several features need to run a host binary rather
# than just compile one (fd passing, epoll, mmap()/write() coherency, fallocate(),
# va_copy, time_t size and signedness). A cross file with an exe_wrapper can run them, so
# only reject when a cross file is not available.
if meson.is_cross_build() and not meson.can_run_host_binaries()
  error('Cross-compiling is not supported without an exe_wrapper, ' +
        'because some feature checks need to run a host binary')
endif

dovecot_project = meson.project_name()
dovecot_version = meson.project_version()
dovecot_build_root = meson.project_build_root()

# Whether the source tree is a git checkout rather than an unpacked tarball. Only a
# tarball ships the generated source code files; a checkout always generates them into the
# build directory, because a copy in the source tree can only be a leftover from an
# autotools build and is not necessarily in sync with the sources. Note that .git is a
# regular file in a git worktree, so this has to test for existence, not for a directory.
have_git_tree = import('fs').exists(meson.project_source_root() / '.git')

dovecot_localstatedir = get_option('prefix') / get_option('localstatedir')
dovecot_sysconfdir = get_option('prefix') / get_option('sysconfdir')
dovecot_bindir = get_option('prefix') / get_option('bindir')
dovecot_includedir = get_option('prefix') / get_option('includedir') / 'dovecot'
# Where libdovecot and dovecot-config are installed.
dovecot_pkglibdir = get_option('prefix') / get_option('libdir') / 'dovecot'

# The package subdirectory is appended here instead of being baked into the defaults of
# the standard options, so that it survives a distro overriding those options.
dovecot_rundir = dovecot_localstatedir / 'run' / 'dovecot'
dovecot_statedir = dovecot_localstatedir / 'lib' / 'dovecot'
dovecot_pkgsysconfdir = dovecot_sysconfdir / 'dovecot'

summary(
  {
    'bin': dovecot_bindir,
    'lib': get_option('libdir'),
    'data': get_option('datadir'),
    'include': dovecot_includedir,
    'run': dovecot_rundir,
    'state': dovecot_statedir,
    'sysconf': dovecot_pkgsysconfdir,
  },
  section: 'Directories',
)

conf = configuration_data()
conf.set_quoted('PACKAGE', dovecot_project)
conf.set_quoted('VERSION', dovecot_version)
conf.set_quoted('DOVECOT_VERSION', dovecot_version)

development_extra_checks = get_option('development-extra-checks')
conf.set(
  'DEBUG',
  development_extra_checks == 'yes',
  description: 'Build with extra debugging checks',
)
conf.set(
  'DEBUG_FAST',
  development_extra_checks != 'no',
  description: 'Build with fast extra debugging checks',
)

conf.set(
  'STATIC_CHECKER',
  get_option('development-static-analysis'),
  description: 'Build with static code analyzer',
)

conf.set(
  'EXPERIMENTAL_MAIL_UTF8',
  get_option('experimental-mail-utf8'),
  description: 'Build with SMTPUTF8 and UTF8=ACCEPT support',
)

subdir('build-aux')

dovecot_abi_version = run_command(
  git_abi_version_gen_script,
  check: true,
).stdout().strip()
conf.set('DOVECOT_ABI_VERSION', dovecot_abi_version)

meson.add_dist_script(
  version_dist_script,
  dovecot_version,
  meson.project_source_root(),
)
subdir('meson' / 'version')
subdir('meson' / 'compiler')
subdir('meson' / 'attributes')
subdir('meson' / 'sanitizers')
subdir('meson' / 'cflags')
subdir('meson' / 'security')
subdir('meson' / 'defines')
subdir('meson' / 'endian')
subdir('meson' / 'libbsd')
subdir('meson' / 'libc')

dovecot_moduledir = get_option('moduledir')
if dovecot_moduledir == ''
  dovecot_moduledir = dovecot_pkglibdir
else
  # Path has to be absolute to allow MODULEDIR to be dlopen()'ed at runtime.
  dovecot_moduledir = get_option('prefix') / dovecot_moduledir
endif

conf.set_quoted('MODULE_SUFFIX', '.so')
conf.set_quoted('MODULEDIR', dovecot_moduledir)

summary(
  {
    'moduledir': dovecot_moduledir,
  },
  section: 'Directories',
)

# Generate dovecot-version.h - TODO: Eventually use vcs_tag() for this.
dovecot_version_h = custom_target(
  'dovecot-version-h',
  build_always_stale: true,
  output: 'dovecot-version.h',
  command: [
    'update-version.sh',
    meson.global_source_root(),
    meson.global_build_root(),
  ],
  install: true,
  install_dir: dovecot_includedir,
)

# Install the autoconf macro file somewhere plugins' DC_DOVECOT/aclocal can find it.
install_data(
  'm4' / 'dovecot.m4',
  install_dir: get_option('datadir') / 'aclocal',
)

# TODO: dovecot-config, the other half of what DC_DOVECOT reads. Autotools generates two
# variants from dovecot-config.in.in (one at Makefile.am:45-59 for the build tree, and one
# at Makefile.am:73-91 for pkglibdir), and most of its LIBDOVECOT_* variables name
# libraries that are not ported yet so it can only be written once those exist.

configure_file(
  output: 'config.h',
  configuration: conf,
  install: true,
  install_dir: dovecot_includedir,
)
