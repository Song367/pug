package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

type options struct {
	URL        string
	CACertFile string
	Timeout    time.Duration
}

func main() {
	var opts options
	flag.StringVar(&opts.URL, "url", "", "absolute HTTP(S) health endpoint")
	flag.StringVar(&opts.CACertFile, "ca-cert", "", "optional PEM CA certificate for HTTPS")
	flag.DurationVar(&opts.Timeout, "timeout", 2*time.Second, "total probe timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	if err := probe(ctx, opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func probe(ctx context.Context, opts options) error {
	if opts.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	target, err := url.Parse(opts.URL)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return errors.New("url must be an absolute HTTP(S) URL")
	}
	if target.User != nil || target.Fragment != "" {
		return errors.New("url must not contain credentials or a fragment")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.CACertFile != "" {
		pem, err := os.ReadFile(opts.CACertFile)
		if err != nil {
			return fmt.Errorf("read CA certificate: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("CA certificate contains no valid PEM certificate")
		}
		tlsConfig.RootCAs = roots
	}

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: tlsConfig,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("health probe refuses redirects")
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return fmt.Errorf("create health request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("health request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("health endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}
