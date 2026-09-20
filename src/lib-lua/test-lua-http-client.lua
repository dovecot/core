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

function test_http_request_set_event(event, url)
  local request = http_client:request {
    url = url,
    method = "POST"
  }
  request:add_header("Cache-Control", "no-cache")
  request:add_header("Content-Type", "application/x-www-form-urlencoded")
  request:set_payload("some+foolish+payload+for+funsies\r\n", true)
  request:set_event(event)
  return request:get_event()
end

function test_http_request_set_no_event(event, url)
  local request = http_client:request {
    url = url,
    method = "POST"
  }
  request:add_header("Cache-Control", "no-cache")
  request:add_header("Content-Type", "application/x-www-form-urlencoded")
  request:set_payload("some+foolish+payload+for+funsies\r\n", true)
  return request:get_event()
end

function http_request_large_payload(url, expect_len)
  local request = http_client:request {
    url = url,
    method = "GET"
  }
  local response = request:submit()

  if response:status() ~= 200 then
    return -1
  end

  local payload = response:payload()
  if #payload ~= expect_len then
    return -2
  end
  if payload:sub(1, 5) ~= "BEGIN" or payload:sub(-3) ~= "END" then
    return -3
  end
  -- everything between the markers must be filler
  if payload:find("[^x]", 6) ~= expect_len - 2 then
    return -4
  end
  -- the response is returned so that the caller can check how much memory
  -- its pool used
  return 0, response
end

function test_request_set_timeouts(url)
  local request = http_client:request {
    url = url,
    method = "POST"
  }
  request:set_timeout("2s")
  request:set_absolute_timeout("10s")
  request:set_max_attempts(1)
  return 0
end

function test_request_invalid_timeout(url)
  local request = http_client:request {
    url = url,
    method = "POST"
  }
  request:set_timeout("cow")
  return 0
end

function test_request_invalid_absolute_timeout(url)
  local request = http_client:request {
    url = url,
    method = "POST"
  }
  request:set_absolute_timeout("10")
  return 0
end

function test_request_invalid_max_attempts(url)
  local request = http_client:request {
    url = url,
    method = "POST"
  }
  request:set_max_attempts(0)
  return 0
end

function test_request_timeout(url)
  local request = http_client:request {
    url = url,
    method = "POST"
  }
  -- much shorter than the client's request_absolute_timeout
  request:set_absolute_timeout("100ms")
  request:add_header("Content-Type", "application/x-www-form-urlencoded")
  request:set_payload("some+foolish+payload+for+funsies\r\n", true)
  local response = request:submit()
  return response:status(), response:reason()
end
