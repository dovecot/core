-- Copyright (c) 2025 Dovecot authors, see the included COPYING files

function test_write_ostream(os)
  os:write("hello, world")
end

function test_read_simple_istream(is)
  local line = is:read()
  test_assert("was able to read", line == "hello, world\n")
  line = is:read()
  test_assert("eof is NULL", line == nil)
end

function test_read_many(is)
  local l1, l2, l3, l4, _ = is:read('l','L','l','L', 1)
  test_assert("l1 == line1", l1 == "line1")
  test_assert("l2 == line2<nl>", l2 == "line2\n")
  test_assert("l3 == line3", l3 == "line3")
  test_assert("l4 == line4<nl>", l4 == "line4\n")
  l1 = is:read()
  l2 = is:read()
  test_assert("l1 == hello<nl>", l1 == "hello\n")
  test_assert("l2 == world<nl>", l2 == "world\n")
  -- test seeking and line iterator
  is:seek('set', 0)
  local i = 1
  for line in is:lines() do
    test_assert("line == line"..tostring(i), line == "line"..tostring(i).."\n")
    i = i + 1
  end
  test_assert("i == 5", i == 5)
  is:read(1)
  l1 = is:read()
  l2 = is:read()
  test_assert("l1 == hello<nl>", l1 == "hello\n")
  test_assert("l2 == world<nl>", l2 == "world\n")
end

function test_read_bytes(is)
  local h,_,w = is:read(5,1,5)
  local r = is:read('a')
  test_assert("h == hello", h == "hello")
  test_assert("w == world", w == "world")
  test_assert("r == \\0\\1\\2\\3\\4\\5", r == "\0\1\2\3\4\5")
  test_assert("#r==6", #r == 6)
end

function test_read_error(is)
  local _, err, errno = is:read(1)
  test_assert("errno == 22", errno == 22)
  test_assert("err = (error): Invalid argument", err == "(error): Invalid argument")
end
