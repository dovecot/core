cc = meson.get_compiler('c')
cxx = meson.get_compiler('cpp')

system = host_machine.system()

have_clang = cc.get_id() == 'clang' or cxx.get_id() == 'clang'

# Don't limit the number of errors when using clang. This is useful to not cut out the
# error output when using an LSP server like clangd.
if have_clang
  add_project_arguments('-ferror-limit=0', language: ['c', 'cpp'])
endif

# -Wstrict-bool is clang-only.
conf.set(
  'HAVE_STRICT_BOOL',
  have_clang and cc.has_argument('-Wstrict-bool'),
  description: 'we have strict bool',
)
