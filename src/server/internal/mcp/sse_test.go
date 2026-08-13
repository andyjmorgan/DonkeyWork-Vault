package mcp

import "testing"

func TestInspectSSEEvent(t *testing.T) {
	tests := []struct {
		name    string
		event   string
		has     bool
		kind    Kind
		wantErr bool
	}{
		{"comment", ": keepalive\r\n\r\n", false, "", false},
		{"metadata only", "event: ping\nid: 3\n\n", false, "", false},
		{"notification", "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\ndata: \"params\":{}}\n\n", true, KindNotification, false},
		{"result", "data:{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n", true, KindResult, false},
		{"blank data", "data:\n\n", false, "", true},
		{"bad data", "data: nope\n\n", false, "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, has, err := InspectSSEEvent([]byte(test.event), nil)
			if has != test.has || (err != nil) != test.wantErr || message.Kind != test.kind {
				t.Fatalf("message=%+v has=%v err=%v", message, has, err)
			}
		})
	}
}

func FuzzInspectClient(f *testing.F) {
	f.Add([]byte(requestBody("1", "tools/list", `"cursor":"x"`)))
	f.Add([]byte(`[]`))
	f.Fuzz(func(_ *testing.T, body []byte) {
		_, _ = InspectClient(body, validHeaders("tools/list", ""), Options{})
	})
}

func FuzzInspectServer(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"notifications/progress"}`))
	f.Fuzz(func(_ *testing.T, body []byte) {
		_, _ = InspectServer(body, nil)
	})
}
