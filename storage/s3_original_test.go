package storage

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func c660S3Fs(t *testing.T, endpoint string, pathStyle bool) *S3Fs {
	t.Helper()
	client := s3.NewFromConfig(aws.Config{
		Region:      "ap-test",
		Credentials: credentials.NewStaticCredentialsProvider("C660TESTACCESS", "C660TESTSECRET", ""),
	}, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(endpoint)
		options.UsePathStyle = pathStyle
	})
	return &S3Fs{
		opt: StorageOption{PresignedTimeout: 90 * time.Second},
		s3fsCfg: S3StorageConfig{
			EndPoint: endpoint, Region: "ap-test", Bucket: "c660-bucket",
			UsePathStyle: pathStyle, OriginalImageCI: true,
		},
		client: client,
	}
}

type c660RecordingPresigner struct {
	inner      s3.HTTPPresignerV4
	called     bool
	signedRaw  string
	signedKeys url.Values
}

func (p *c660RecordingPresigner) PresignHTTP(
	ctx context.Context, credentials aws.Credentials, request *http.Request,
	payloadHash, service, region string, signingTime time.Time,
	optFns ...func(*v4.SignerOptions),
) (string, http.Header, error) {
	p.called = true
	p.signedRaw = request.URL.RawQuery
	p.signedKeys = request.URL.Query()
	return p.inner.PresignHTTP(ctx, credentials, request, payloadHash, service, region, signingTime, optFns...)
}

func TestC660OriginalPresignUsesSDKSigningAndKeepsObjectKey(t *testing.T) {
	store := c660S3Fs(t, "https://cos.example.com", false)
	keys := []string{
		"project23/file68.png",
		"project23/a b+c/中文%/file 1.png",
		"project23/dir+plus/100%/a%2Fb.png",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			recorder := &c660RecordingPresigner{inner: v4.NewSigner()}
			signed, err := store.presignOriginalObject(context.Background(), key,
				func(options *s3.PresignOptions) { options.Presigner = recorder })
			if err != nil {
				t.Fatalf("presign original object: %v", err)
			}
			if !recorder.called || recorder.signedKeys.Get("ci-process") != "originImage" {
				t.Fatalf("ci-process was not present at the SDK signing boundary")
			}
			parsed, err := url.Parse(signed.URL)
			if err != nil {
				t.Fatalf("parse signed URL: %v", err)
			}
			if parsed.Host != "c660-bucket.cos.example.com" {
				t.Fatalf("signed host=%q", parsed.Host)
			}
			wantPath := (&url.URL{Path: "/" + key}).EscapedPath()
			// The SDK's path encoder escapes '+' as %2B; both forms address
			// the same object, and this is not double escaping.
			wantPath = strings.ReplaceAll(wantPath, "+", "%2B")
			if parsed.EscapedPath() != wantPath {
				t.Fatalf("object key path=%q, want %q", parsed.EscapedPath(), wantPath)
			}
			if parsed.Path != "/"+key {
				t.Fatalf("decoded object key path=%q, want %q", parsed.Path, "/"+key)
			}
			query := parsed.Query()
			if query.Get("ci-process") != "originImage" || query.Get("X-Amz-Signature") == "" {
				t.Fatalf("signed URL missing original query or signature")
			}
			if strings.Contains(recorder.signedRaw, "ci-process=originImage%") {
				t.Fatalf("ci-process was double encoded at signing boundary")
			}
		})
	}
}

func TestC660OrdinaryGetDoesNotUseOriginalQuery(t *testing.T) {
	store := c660S3Fs(t, "https://cos.example.com", false)
	signed, err := store.GetPresignedURL(context.Background(), http.MethodGet, "project23/file68.png")
	if err != nil {
		t.Fatalf("ordinary presign: %v", err)
	}
	parsed, err := url.Parse(signed)
	if err != nil {
		t.Fatalf("parse ordinary URL: %v", err)
	}
	if parsed.Query().Get("ci-process") != "" {
		t.Fatalf("ordinary presign unexpectedly uses original-image query")
	}
}

func TestC660OriginalPresignRequiresOptInAndGet(t *testing.T) {
	store := c660S3Fs(t, "https://cos.example.com", false)
	store.s3fsCfg.OriginalImageCI = false
	if _, err := store.GetPresignedOriginalURL(context.Background(), http.MethodGet, "project23/file68.png"); err == nil {
		t.Fatal("GetPresignedOriginalURL accepted disabled original-image CI")
	}
	store.s3fsCfg.OriginalImageCI = true
	if _, err := store.GetPresignedOriginalURL(context.Background(), http.MethodPut, "project23/file68.png"); err == nil {
		t.Fatal("GetPresignedOriginalURL accepted PUT")
	}
	if _, err := store.GetPresignedOriginalURL(context.Background(), http.MethodGet, ""); err == nil {
		t.Fatal("GetPresignedOriginalURL accepted an empty path")
	}
	var zero S3Fs
	if zero.OriginalFileSupported() {
		t.Fatal("zero S3Fs enabled billable original-image CI")
	}
}

func TestC660ReadOriginalFileErrorDoesNotLeakSignedURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unused", http.StatusInternalServerError)
	}))
	store := c660S3Fs(t, server.URL, true)
	server.Close()

	_, err := store.ReadOriginalFile(context.Background(), "project23/a b.png")
	if err == nil {
		t.Fatal("ReadOriginalFile unexpectedly succeeded against a closed server")
	}
	text := err.Error()
	for _, forbidden := range []string{server.URL, "http://", "https://", "ci-process", "X-Amz", "Signature", "Credential", "C660TESTACCESS"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("read error leaked %q: %s", forbidden, text)
		}
	}
}

func TestC660OriginalReadErrorPreservesCancellation(t *testing.T) {
	signed := "https://cos.example.com/project23/file68.png?ci-process=originImage&X-Amz-Signature=FAKESIG&X-Amz-Credential=C660TESTACCESS"
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		err := originalReadTransportError(&url.Error{Op: "Get", URL: signed, Err: cause})
		if !errors.Is(err, cause) {
			t.Fatalf("cause %v not preserved: %v", cause, err)
		}
		text := err.Error()
		for _, forbidden := range []string{"cos.example.com", "ci-process", "X-Amz", "FAKESIG", "C660TESTACCESS"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("redacted error leaked %q: %s", forbidden, text)
			}
		}
	}
}
