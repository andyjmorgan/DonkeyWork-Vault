package mcp

import (
	"bytes"
	"errors"
	"strings"
)

// InspectSSEEvent parses one complete SSE event and classifies its JSON-RPC data payload.
// Comment-only keep-alives return hasMessage false.
func InspectSSEEvent(event []byte, requestStateHMACKey []byte) (message ServerMessage, hasMessage bool, err error) {
	var data []string
	for _, rawLine := range bytes.Split(event, []byte{'\n'}) {
		line := strings.TrimSuffix(string(rawLine), "\r")
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			field, value = line, ""
		} else if strings.HasPrefix(value, " ") {
			value = value[1:]
		}
		if field == "data" {
			data = append(data, value)
		}
	}
	if len(data) == 0 {
		return ServerMessage{}, false, nil
	}
	payload := strings.Join(data, "\n")
	if strings.TrimSpace(payload) == "" {
		return ServerMessage{}, false, &ValidationError{Kind: ErrorInvalidJSON, Field: "SSE data", err: errors.New("empty data")}
	}
	parsed, err := InspectServer([]byte(payload), requestStateHMACKey)
	return parsed, err == nil, err
}
