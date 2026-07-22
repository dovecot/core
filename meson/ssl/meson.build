fs = import('fs')
ext_ssl = dependency('openssl', version: '>= 1.1.1', required: false)

if not ext_ssl.found()
  ssl_headers = ['openssl/ssl.h', 'openssl/err.h']
  ext_libssl = cc.find_library('ssl', has_headers: ssl_headers, required: false)
  ext_libcrypto = cc.find_library('crypto', required: false)

  if ext_libssl.found() and ext_libcrypto.found() and cc.has_function(
    'SSL_read',
    dependencies: [ext_libssl, ext_libcrypto],
    prefix: fs.read('openssl-basic-headers.c'),
  )
    ext_ssl = declare_dependency(dependencies: [ext_libssl, ext_libcrypto, ext_dl])
  endif
endif

if not ext_ssl.found()
  error('Cannot build with OpenSSL: libssl not found')
endif

if cc.compiles(
  fs.read('openssl-version-3.0.0.c'),
  dependencies: ext_ssl,
  name: 'OpenSSL v3.0.0',
)
  ext_ssl = declare_dependency(
    compile_args: [
      '-DOPENSSL_NO_DEPRECATED',
      '-DOPENSSL_API_COMPAT=30000',
      '-DDOVECOT_USE_OPENSSL3',
    ],
    dependencies: ext_ssl,
  )
  conf.set10('HAVE_OPENSSL3', true)
elif cc.compiles(
  fs.read('openssl-version-1.1.1.c'),
  dependencies: ext_ssl,
  name: 'OpenSSL v1.1.1',
  required: true,
)
  ext_ssl = declare_dependency(
    compile_args: ['-DOPENSSL_NO_DEPRECATED', '-DOPENSSL_API_COMPAT=0x1000200L'],
    dependencies: ext_ssl,
  )
endif

if cc.links(
  fs.read('openssl-new-style-mem-functions.c'),
  dependencies: ext_ssl,
  name: 'OpenSSL new-style memory functions',
)
  conf.set('HAVE_SSL_NEW_MEM_FUNCS', true)
endif

functions = [
  # OpenSSL 3.0
  'ERR_get_error_all',
  'EVP_MAC_CTX_new',
  'OSSL_PROVIDER_try_load',
  'ENGINE_by_id',
  'SSL_CTX_set_tmp_dh_callback',
  'SSL_CTX_set_current_cert',
  'SSL_CTX_set0_tmp_dh_pkey',

  # LibreSSL
  'EVP_PKEY_check',
  'OPENSSL_buf2hexstr',
  'SSL_get1_peer_certificate',
  'SSL_CTX_set_client_hello_cb',
  'SSL_CTX_select_current_cert',
  'SSL_client_hello_get0_ciphers',
  'SSL_CTX_set_alpn_select_cb',
]

openssl_headers = fs.read('openssl-headers.c')

foreach func: functions
  conf.set(
    f'HAVE_@func@',
    cc.has_header_symbol(
      'openssl/ssl.h',
      func,
      prefix: openssl_headers,
      dependencies: ext_ssl,
    ),
    description: f'Have OpenSSL @func@',
  )
endforeach
