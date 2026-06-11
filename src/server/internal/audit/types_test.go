package audit

import (
	"context"
	"testing"
)

func TestEventTypeString(t *testing.T) {
	for tp := EventUnknown; tp <= EventTokenRemoved; tp++ {
		if tp.String() == "" {
			t.Fatalf("missing string for %d", tp)
		}
		parsed, ok := ParseEventType(tp.String())
		if tp == EventUnknown {
			continue
		}
		if !ok || parsed != tp {
			t.Fatalf("roundtrip failed for %v", tp)
		}
	}
	if _, ok := ParseEventType("nope"); ok {
		t.Fatal("expected unknown parse to fail")
	}
	if EventType(99).String() != "Unknown" {
		t.Fatal("out-of-range should be Unknown")
	}
}

func TestOutcomeString(t *testing.T) {
	if OutcomeSuccess.String() != "Success" || OutcomeFailure.String() != "Failure" {
		t.Fatal("outcome strings")
	}
	if o, ok := ParseOutcome("success"); !ok || o != OutcomeSuccess {
		t.Fatal("parse success")
	}
	if o, ok := ParseOutcome("FAILURE"); !ok || o != OutcomeFailure {
		t.Fatal("parse failure")
	}
	if _, ok := ParseOutcome("maybe"); ok {
		t.Fatal("parse invalid")
	}
}

func TestRequestInfoCtx(t *testing.T) {
	if got := RequestInfoFrom(context.Background()); got.Transport != "unknown" {
		t.Fatal("default transport")
	}
	ip := "1.2.3.4"
	ctx := WithRequestInfo(context.Background(), RequestInfo{SourceIP: &ip, Transport: "http"})
	if RequestInfoFrom(ctx).Transport != "http" {
		t.Fatal("roundtrip")
	}
}
