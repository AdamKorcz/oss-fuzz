package caddyfile

func testParser(input string) parser {
	return parser{Dispenser: NewTestDispenser(input)}
}

func FuzzParser(data []byte) int {
	p := testParser(string(data))
	p.Next()
	_ = p.parseOne()
	return 1
}
