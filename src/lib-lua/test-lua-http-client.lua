local json = require 'json'
local http_client

function http_request_post(url)
  local request = http_client:request {
    url = url,
    method = "POST"
  }

  request:add_header("Cache-Control", "no-cache")
  request:add_header("Content-Type", "application/x-www-form-urlencoded")
  request:set_payload("some+foolish+payload+for+funsies", true)
  local response = request:submit()

  e = dovecot.event()

  local status = response:status()
  if status ~= 200 then
    e:log_debug("HTTP error: " .. status .. " " .. response:reason())
    e:log_debug("HTTP error response: " .. response:payload())
    return -1
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
  http_client = dovecot.http.client({
    max_attempts = 3,
    connect_timeout_msecs = 2000,
    request_timeout_msecs = 5000,
    request_absolute_timeout_msecs = 45000,
    dns_client_socket_path = "./dns-test"
  })
  return 0
end
