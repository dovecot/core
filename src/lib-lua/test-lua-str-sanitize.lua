function test_str_sanitize()
	-- short enough input is returned as-is
	test_assert("no truncation", dovecot.str_sanitize("hello", 10) == "hello")
	test_assert("no truncation utf8",
		    dovecot.str_sanitize_utf8("hello", 10) == "hello")

	-- control characters are replaced
	test_assert("control chars",
		    dovecot.str_sanitize("a\tb", 10) == "a?b")
	test_assert("control chars utf8",
		    dovecot.str_sanitize_utf8("a\tb", 10) == "a\u{fffd}b")

	-- too long input is truncated, max_bytes includes the "..."
	local truncated = dovecot.str_sanitize("abcdefghij", 8)
	test_assert("truncated = \"" .. truncated .. "\"", truncated == "abcde...")

	-- max_cps counts characters, not bytes
	local utf8_str = "\u{00e4}\u{00e4}\u{00e4}\u{00e4}"
	test_assert("utf8 not truncated",
		    dovecot.str_sanitize_utf8(utf8_str, 4) == utf8_str)
	test_assert("utf8 truncated",
		    dovecot.str_sanitize_utf8(utf8_str, 3) ==
		    "\u{00e4}\u{00e4}\u{2026}")

	-- a multibyte character is never split in half
	local cut = dovecot.str_sanitize(utf8_str, 6)
	test_assert("cut = \"" .. cut .. "\"", cut == "\u{00e4}...")
end
