# dlopen() is in libc on the BSDs, macOS and glibc >= 2.34, and in libdl elsewhere.
ext_dl = declare_dependency()

if not cc.has_function('dlopen')
  ext_dl = cc.find_library('dl', required: false)
  cc.has_function('dlopen', dependencies: ext_dl, required: true)
endif

if cc.has_link_argument('-Wl,--export-dynamic')
  ext_dl = declare_dependency(
    dependencies: ext_dl,
    link_args: ['-Wl,--export-dynamic'],
  )
endif
