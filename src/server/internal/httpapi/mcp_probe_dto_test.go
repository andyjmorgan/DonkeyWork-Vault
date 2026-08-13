package httpapi

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

func TestMCPConnectionDTOProbeFields(t *testing.T) {
	checkedAt := time.Now().UTC()
	probeError, probeDetail := "safe_error", "safe_detail"
	serverName, serverVersion := "Acme MCP", "1.2.3"
	dto := toMCPConnectionDTO(store.MCPConnection{
		ID: uuid.New(), ProtocolEra: "modern_2026_07", ProbeStatus: "compatible",
		ProbeCheckedAt: &checkedAt, ProbeError: &probeError, ProbeDetail: &probeDetail,
		SupportedVersions: []string{"2026-07-28"}, ServerName: &serverName, ServerVersion: &serverVersion,
	})
	if dto.ProtocolEra != "modern_2026_07" || dto.ProbeStatus != "compatible" ||
		dto.ProbeCheckedAt == nil || dto.ProbeError == nil || dto.ProbeDetail == nil ||
		len(dto.SupportedVersions) != 1 || dto.ServerName == nil || dto.ServerVersion == nil {
		t.Fatalf("probe DTO: %+v", dto)
	}

	empty := toMCPConnectionDTO(store.MCPConnection{})
	if empty.SupportedVersions == nil {
		t.Fatal("supportedVersions must encode as [] rather than null")
	}
	body, err := json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	if string(envelope["supportedVersions"]) != "[]" {
		t.Fatalf("supportedVersions JSON: %s", envelope["supportedVersions"])
	}
}
