opt_gssapi = get_option('gssapi')

# 'enabled' and 'plugin' are hard requests, so a failed check is an error; 'auto' falls
# back to no GSSAPI.
gssapi_wanted = opt_gssapi != 'disabled'
gssapi_required = opt_gssapi in ['enabled', 'plugin']

have_gssapi = false
ext_gssapi = dependency('', required: false)

if gssapi_wanted
  # MIT and Heimdal both ship pkg-config files nowadays. Use krb5-config as the fallback.
  ext_gssapi = dependency(
    'krb5-gssapi',
    'mit-krb5-gssapi',
    'heimdal-gssapi',
    required: false,
  )

  if not ext_gssapi.found()
    krb5_config = find_program('krb5-config', required: gssapi_required)

    if krb5_config.found()
      # Not every krb5-config knows the gssapi module. Where it does not, autoconf fell
      # back to the bare krb5 libraries plus Solaris' separate -lgss.
      have_gssapi_module = run_command(
        krb5_config,
        '--version',
        'gssapi',
        check: false,
      ).returncode() == 0

      if have_gssapi_module
        krb5_cflags = run_command(krb5_config, '--cflags', 'gssapi', check: true)
        krb5_libs = run_command(krb5_config, '--libs', 'gssapi', check: true)
      else
        krb5_cflags = run_command(krb5_config, '--cflags', check: true)
        krb5_libs = run_command(krb5_config, '--libs', check: true)
      endif

      gssapi_compile_args = krb5_cflags.stdout().split()
      gssapi_link_args = krb5_libs.stdout().split()

      if not have_gssapi_module
        if cc.has_function(
          'gss_acquire_cred',
          args: gssapi_link_args + ['-lgss'],
        )
          gssapi_link_args += '-lgss'
        else
          gssapi_link_args = []
        endif
      endif

      if gssapi_link_args.length() > 0
        ext_gssapi = declare_dependency(
          compile_args: gssapi_compile_args,
          link_args: gssapi_link_args,
        )
      endif
    endif
  endif
endif

# krb5-config or a .pc file existing does not mean the system actually has gssapi.h.
gssapi_headers = [
  {'header': 'gssapi/gssapi.h',      'symbol': 'HAVE_GSSAPI_GSSAPI_H',      'api': true},
  {'header': 'gssapi.h',             'symbol': 'HAVE_GSSAPI_H',             'api': true},
  {'header': 'gssapi/gssapi_ext.h',  'symbol': 'HAVE_GSSAPI_GSSAPI_EXT_H',  'api': false},
  {'header': 'gssapi/gssapi_krb5.h', 'symbol': 'HAVE_GSSAPI_GSSAPI_KRB5_H', 'api': false},
  {'header': 'gssapi_krb5.h',        'symbol': 'HAVE_GSSAPI_KRB5_H',        'api': false},
]

if ext_gssapi.found()
  foreach entry : gssapi_headers
    header = entry['header']
    found = cc.has_header(header, dependencies: ext_gssapi)

    conf.set(entry['symbol'], found, description: f'GSSAPI headers in @header@')

    # Only the headers that declare the GSSAPI API itself decide whether it is usable.
    if found and entry['api']
      have_gssapi = true
    endif
  endforeach
endif

if gssapi_required and not have_gssapi
  error('Cannot build with GSSAPI support: gssapi.h not found')
endif

if not have_gssapi
  ext_gssapi = dependency('', required: false)
endif

conf.set('HAVE_GSSAPI', have_gssapi, description: 'Build with GSSAPI support')

if have_gssapi
  # MIT has a #define for Heimdal's acceptor_identity name, so probe both spellings.
  foreach func : [
    'gsskrb5_register_acceptor_identity',
    'krb5_gss_register_acceptor_identity',
  ]
    symbol = func.to_upper().underscorify()

    conf.set(
      f'HAVE_@symbol@',
      cc.has_function(func, dependencies: ext_gssapi),
      description: f'Have @func@',
    )
  endforeach

  # TODO: HAVE_GSSAPI_SPNEGO and GSSAPI_PLUGIN are only consumed by src/auth and
  # src/doveadm, neither of which is ported yet. SPNEGO needs a run probe of
  # gss_indicate_mechs(), so it is left out until there is a consumer.
  conf.set('BUILTIN_GSSAPI', opt_gssapi != 'plugin',
           description: 'GSSAPI support is built in')
endif

summary({'GSSAPI': have_gssapi}, bool_yn: true, section: 'Features')
