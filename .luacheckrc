std = "lua53+lua54"

files["src"] = {
  read_globals = {
    "dovecot",
    "cluster",
    "json",
    "test_assert",
  },
}

files["src/lib-lua/test-io-lua.lua"] = {
  new_globals = {
    "test_write_ostream",
    "test_read_simple_istream",
    "test_read_many",
    "test_read_bytes",
  },
}

files["src/lib-lua/test-lua-base64.lua"] = {
  new_globals = {
    "test_base64",
  }
}

files["src/lib-lua/test-lua-http-client.lua"] = {
  new_globals = {
    "http_request_post",
    "script_init",
    "test_invalid_set_name",
    "test_invalid_set_value_1",
    "test_invalid_set_value_2",
    "test_invalid_set_value_3",
  },
}
