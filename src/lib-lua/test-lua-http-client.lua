local json = require 'json'
local http_client

function http_request_post(url)
  local request = http_client:request {
    url = url,
    method = "POST"
  }

  request:add_header("Cache-Control", "no-cache")
  request:add_header("Content-Type", "application/x-www-form-urlencoded")
  request:set_payload("some+foolish+payload+for+funsies\r\n", true)
  local response = request:submit()

  local e = dovecot.event()

  local status = response:status()
  if status ~= 200 then
    e:log_debug("HTTP error: " .. status .. " " .. response:reason())
    e:log_debug("HTTP error response: " .. response:payload())
    return -1, response:reason()
  end

  local payload = response:payload()
  local ok, result = pcall(json.decode, payload)
  if not ok then
    e:log_error("Could not parse JSON response: " .. result)
    e:log_debug("Server response: " .. payload)
    return -2
  end

  e:log_debug("Server response: " .. json.encode(result))
  return 0
end

function script_init()
  local e = dovecot.event()
  http_client = dovecot.http.client({
    event_parent = e,
    request_max_attempts = 3,
    connect_timeout = "2s",
    request_timeout = "5s",
    request_absolute_timeout = "45s",
    dns_client_socket_path = "./dns-test",
    user_agent = "dovecot/unit-test",
    ssl_min_protocol = "TLSv1.2",
  })
  return 0
end

function test_invalid_set_name()
  http_client = dovecot.http.client({
    timeout = 10000,
  })
  return 0
end

function test_invalid_set_value_1()
  http_client = dovecot.http.client({
    auto_retry = "cow"
  })
  return 0
end

function test_invalid_set_value_2()
  http_client = dovecot.http.client({
    request_max_attempts = "three"
  })
  return 0
end

function test_invalid_set_value_3()
  http_client = dovecot.http.client({
    ssl_min_protocol = "cow",
  })
  return 0
end
