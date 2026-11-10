package pvcore

import "testing"

// the same golden values as server/linux/test_pv_agent.py
func TestGolden(t *testing.T) {
	cases := map[string][2]string{
		"vless":  {VlessUUID("25g00001", "abc123"), "f4faf53d-9ec0-58d6-9711-c9cabcc6e4b5"},
		"hy2":    {Hy2Auth("25g00001", "abc123"), "100720b0c2b0f243637b6979f25c35e7"},
		"ss":     {SSKey("25g00001", "abc123"), "kIPsqZJOWdJYPjSbZ7zSrQ=="},
		"awg":    {AwgPrivate("25g00001", "abc123"), "iEOjwrLAGYLR3gCJd8hsCtL+1cqeTz1lO1EWQXlQYlw="},
		"awg_ip": {AwgAddress("25G00001 "), "10.122.173.75"},
		"case":   {VlessUUID(" 25G00001", "abc123"), "f4faf53d-9ec0-58d6-9711-c9cabcc6e4b5"},
	}
	for name, c := range cases {
		if c[0] != c[1] {
			t.Errorf("%s: got %s want %s", name, c[0], c[1])
		}
	}
}
