package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbeAcceptsHealthyEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := probe(context.Background(), options{URL: server.URL, Timeout: time.Second}); err != nil {
		t.Fatalf("probe() error = %v", err)
	}
}

func TestProbeRejectsUnhealthyEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	err := probe(context.Background(), options{URL: server.URL, Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("probe() error = %v, want HTTP 503", err)
	}
}

func TestProbeRejectsCredentialBearingURL(t *testing.T) {
	err := probe(context.Background(), options{URL: "http://user:secret@example.test/healthz", Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("probe() error = %v, want credential rejection", err)
	}
}
