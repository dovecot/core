function test_base64()
	local input = "test value"
	local result = "dGVzdCB2YWx1ZQ=="

	local encoded = dovecot.base64.encode(input)
	test_assert("encoded = \" .. result .. \"", encoded == result)
	local output = dovecot.base64.decode(encoded)
	test_assert("output = \" .. input .. \"", output == input)
end
