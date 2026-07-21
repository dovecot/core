ext_rquota = dependency('', required: false)
prog_rpcgen = find_program('rpcgen', required: false)

if cc.has_header('rpcsvc' / 'rquota.x') and prog_rpcgen.found()
  ext_libtirpc = dependency('libtirpc', required: false)
  if ext_libtirpc.found()
    ext_rquota = declare_dependency(dependencies: ext_libtirpc)
  endif
elif cc.has_header('rpc' / 'rpc.h')
  ext_rquota = declare_dependency()
endif

if ext_rquota.found()
  conf.set10('HAVE_RQUOTA', true)
endif

ext_quota = cc.find_library('quota', required : false)

if ext_quota.found() and cc.has_function('quota_open', dependencies: ext_quota)
  ext_rquota = declare_dependency(dependencies: [ext_rquota, ext_quota])
  conf.set10('HAVE_QUOTA_OPEN', true)
endif

summary({'rquota': ext_rquota}, section: 'Features')
summary({'quota': ext_quota}, section: 'Features')
