package telemetry

import "testing"

func TestNormalizeEndpoint(t *testing.T) {
	cases := []struct {
		name      string
		endpoint  string
		insecure  bool
		wantEP    string
		wantInsec bool
	}{
		{"http prefix forces insecure", "http://collector:4318", false, "collector:4318", true},
		{"http prefix with trailing slash", "http://collector:4318/", false, "collector:4318", true},
		{"https prefix keeps insecure false", "https://collector:4318", false, "collector:4318", false},
		{"https prefix honours insecure true", "https://collector:4318/", true, "collector:4318", true},
		{"bare host:port keeps insecure false", "collector:4318", false, "collector:4318", false},
		{"bare host:port honours insecure true", "collector:4318", true, "collector:4318", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ep, insec := normalizeEndpoint(c.endpoint, c.insecure)
			if ep != c.wantEP {
				t.Errorf("endpoint = %q, want %q", ep, c.wantEP)
			}
			if insec != c.wantInsec {
				t.Errorf("insecure = %v, want %v", insec, c.wantInsec)
			}
		})
	}
}

func TestSetupWithHTTPSchemeEndpoint(t *testing.T) {
	// Drives the http:// branch of normalizeEndpoint through Setup, exercising exporter construction.
	p, err := Setup(t.Context(), Config{OTLPEndpoint: "http://127.0.0.1:4318/", ServiceVersion: "v", Environment: "test"})
	if err != nil {
		t.Fatalf("setup with http endpoint: %v", err)
	}
	_ = p.Shutdown(t.Context())
}

func TestSetupWithHTTPSSchemeEndpoint(t *testing.T) {
	p, err := Setup(t.Context(), Config{OTLPEndpoint: "https://127.0.0.1:4318", Insecure: true, ServiceVersion: "v", Environment: "test"})
	if err != nil {
		t.Fatalf("setup with https endpoint: %v", err)
	}
	_ = p.Shutdown(t.Context())
}
