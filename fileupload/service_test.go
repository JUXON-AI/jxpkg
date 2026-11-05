package fileupload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/identity"
	"github.com/JUXON-AI/jxpkg/storage"
)

func TestStartMultipartAndAbortOnSessionInsertFailure(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("multipart-content")
	request := testRequest(owner, payload)
	request.AllowMultipart = true
	request.SizeBytes = 64
	request.SHA256 = digestString(bytes.Repeat([]byte{1}, 64))
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	repository.createErr = errors.New("temporary insert failure")
	service := mustTestService(t, repository, objectStore, clock, Options{
		MultipartThreshold: 16,
		PartSize:           16,
		CompletionTimeout:  time.Minute,
		CleanupGrace:       time.Hour,
	})

	_, err := service.Start(context.Background(), request)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Start() error = %v, want ErrUnavailable", err)
	}
	objectStore.mu.Lock()
	defer objectStore.mu.Unlock()
	if objectStore.createMultipartCalls != 1 || objectStore.abortMultipartCalls != 1 {
		t.Fatalf("multipart calls = create:%d abort:%d", objectStore.createMultipartCalls, objectStore.abortMultipartCalls)
	}
}

func TestCompleteUsesStreamingDigestInsteadOfETagAndIsIdempotent(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	wantPayload := []byte("verified payload")
	request := testRequest(owner, wantPayload)
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	service := mustTestService(t, repository, objectStore, clock, defaultTestOptions(clock))

	started, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(started.Session.StoragePath, []byte("different payload"), request.MIMEType, request.SHA256)
	_, err = service.Complete(context.Background(), owner, request.ID, nil, nil)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Complete() with matching ETag but wrong content error = %v, want ErrIntegrity", err)
	}
	objectStore.put(started.Session.StoragePath, wantPayload, request.MIMEType, "not-a-digest")
	first, err := service.Complete(context.Background(), owner, request.ID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Hash != "sha256:"+request.SHA256 || first.Size != request.SizeBytes || first.StoragePath != started.Session.StoragePath {
		t.Fatalf("completed file = %#v", first)
	}
	second, err := service.Complete(context.Background(), owner, request.ID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == 0 || second.ID != first.ID {
		t.Fatalf("duplicate Complete() file IDs = %d, %d", first.ID, second.ID)
	}
	if repository.fileCount() != 1 {
		t.Fatalf("file count = %d, want 1", repository.fileCount())
	}
	clock.advance(2 * time.Hour)
	afterExpiry, err := service.Complete(context.Background(), owner, request.ID, nil, nil)
	if err != nil || afterExpiry.ID != first.ID {
		t.Fatalf("Complete() after expiry = %#v, %v; want completed file %d", afterExpiry, err, first.ID)
	}
}

func TestDefaultVerifierComputesDigestWhenRequestSHAIsEmpty(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("digest computed by sdk")
	request := testRequest(owner, payload)
	request.SHA256 = ""
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	service := mustTestService(t, newMemoryRepository(clock), objectStore, clock, defaultTestOptions(clock))
	started, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(started.Session.StoragePath, payload, request.MIMEType, "etag-is-not-digest")
	file, err := service.Complete(context.Background(), owner, request.ID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if file.Hash != "sha256:"+digestString(payload) {
		t.Fatalf("Hash = %q, want computed SHA256", file.Hash)
	}
	invalidSHA := testRequest(owner, payload)
	invalidSHA.ID = "00000000-0000-4000-8000-000000000008"
	invalidSHA.SHA256 = "not-a-sha256"
	if _, err := service.Start(context.Background(), invalidSHA); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Start(invalid non-empty SHA) error = %v, want ErrInvalidRequest", err)
	}

	strictMIME := testRequest(owner, payload)
	strictMIME.ID = "00000000-0000-4000-8000-000000000009"
	strictMIME.MIMEType = "text/markdown"
	strictMIME.SHA256 = ""
	strictStart, err := service.Start(context.Background(), strictMIME)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(strictStart.Session.StoragePath, payload, "text/plain; charset=utf-8", "etag")
	if _, err := service.Complete(context.Background(), owner, strictMIME.ID, nil, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("default verifier MIME mismatch error = %v, want ErrIntegrity", err)
	}
}

func TestTrustedVerifierNormalizesMIMEAndCanReuseDifferentExtension(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("# markdown")
	request := testRequest(owner, payload)
	request.FileExt = ".jpeg"
	request.MIMEType = "text/markdown"
	request.SHA256 = ""
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	service := mustTestService(t, newMemoryRepository(clock), objectStore, clock, defaultTestOptions(clock))
	started, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	canonicalPath := request.Purpose + "/20261105/shared-content.jpg"
	file, err := service.Complete(context.Background(), owner, request.ID, nil, func(context.Context, *Session, ObjectStorage) (VerifiedObject, error) {
		return VerifiedObject{
			SizeBytes: request.SizeBytes, SHA256: digestString(payload), MIMEType: "text/plain; charset=utf-8", StoragePath: canonicalPath,
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if file.MIMEType != "text/plain; charset=utf-8" || file.StoragePath != canonicalPath || file.Hash != "sha256:"+digestString(payload) {
		t.Fatalf("trusted verifier file = %#v", file)
	}
	if started.Session.StoragePath == canonicalPath {
		t.Fatal("canonical trusted path was not distinct from default session path")
	}
}

func TestRegisterExistingAllowsEmptyRequestSHAWithTrustedDigest(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("register without client digest")
	request := testRequest(owner, payload)
	request.ID = "00000000-0000-4000-8000-000000000007"
	request.SHA256 = ""
	path, err := storage.GenerateFileStoragePath(request.Purpose, owner, request.FileExt)
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	service := mustTestService(t, newMemoryRepository(clock), newMemoryStorage(), clock, defaultTestOptions(clock))
	file, err := service.RegisterExisting(context.Background(), request, VerifiedObject{
		SizeBytes: request.SizeBytes, SHA256: digestString(payload), MIMEType: request.MIMEType, StoragePath: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	if file.Hash != "sha256:"+digestString(payload) {
		t.Fatalf("Hash = %q", file.Hash)
	}
}

func TestCompleteAndAbortRaceOnlyOneAcquiresLease(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("race payload")
	request := testRequest(owner, payload)
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	service := mustTestService(t, repository, objectStore, clock, defaultTestOptions(clock))
	started, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(started.Session.StoragePath, payload, request.MIMEType, "etag")
	entered := make(chan struct{})
	release := make(chan struct{})
	completeResult := make(chan error, 1)
	go func() {
		_, err := service.Complete(context.Background(), owner, request.ID, nil, func(context.Context, *Session, ObjectStorage) (VerifiedObject, error) {
			close(entered)
			<-release
			return VerifiedObject{SizeBytes: request.SizeBytes, SHA256: request.SHA256, MIMEType: request.MIMEType, StoragePath: started.Session.StoragePath}, nil
		})
		completeResult <- err
	}()
	<-entered
	if err := service.Abort(context.Background(), owner, request.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("Abort() during Complete error = %v, want ErrConflict", err)
	}
	close(release)
	if err := <-completeResult; err != nil {
		t.Fatal(err)
	}
	if err := service.Abort(context.Background(), owner, request.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("Abort() completed error = %v, want ErrConflict", err)
	}
}

func TestCompleteRecoversMergedObjectAfterFinalizeFailure(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("0123456789abcdef0123456789abcdef")
	request := testRequest(owner, payload)
	request.AllowMultipart = true
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	repository.finalizeFailures = 1
	service := mustTestService(t, repository, objectStore, clock, Options{
		MultipartThreshold: 8,
		PartSize:           16,
		CompletionTimeout:  time.Minute,
		CleanupGrace:       time.Hour,
	})
	started, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(started.Session.StoragePath, payload, request.MIMEType, "etag")
	parts := []storage.MultipartUploadPart{{PartNumber: 1, ETag: "part-1"}, {PartNumber: 2, ETag: "part-2"}}
	_, err = service.Complete(context.Background(), owner, request.ID, parts, nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first Complete() error = %v, want ErrUnavailable", err)
	}
	objectStore.failMultipartComplete = true
	file, err := service.Complete(context.Background(), owner, request.ID, parts, nil)
	if err != nil {
		t.Fatalf("retry Complete() error = %v", err)
	}
	if file.ID == 0 || repository.fileCount() != 1 {
		t.Fatalf("retry file = %#v, count=%d", file, repository.fileCount())
	}
	again, err := service.Complete(context.Background(), owner, request.ID, parts, nil)
	if err != nil || again.ID != file.ID {
		t.Fatalf("duplicate retry = %#v, %v", again, err)
	}
	objectStore.mu.Lock()
	completeCalls := objectStore.completeMultipartCalls
	objectStore.mu.Unlock()
	if completeCalls != 2 {
		t.Fatalf("multipart complete calls = %d, want 2", completeCalls)
	}
}

func TestExpiredLeaseFencesSlowComplete(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("lease fencing payload")
	request := testRequest(owner, payload)
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	service := mustTestService(t, repository, objectStore, clock, defaultTestOptions(clock))
	started, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(started.Session.StoragePath, payload, request.MIMEType, "etag")
	entered := make(chan struct{})
	release := make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		_, err := service.Complete(context.Background(), owner, request.ID, nil, func(context.Context, *Session, ObjectStorage) (VerifiedObject, error) {
			close(entered)
			<-release
			return VerifiedObject{SizeBytes: request.SizeBytes, SHA256: request.SHA256, MIMEType: request.MIMEType, StoragePath: started.Session.StoragePath}, nil
		})
		firstResult <- err
	}()
	<-entered
	clock.advance(2 * time.Minute)
	file, err := service.Complete(context.Background(), owner, request.ID, nil, nil)
	if err != nil {
		t.Fatalf("second Complete() error = %v", err)
	}
	close(release)
	if err := <-firstResult; err != nil {
		t.Fatalf("stale Complete() error = %v, want idempotent success", err)
	}
	if repository.fileCount() != 1 || file.ID == 0 {
		t.Fatalf("files after fencing = %d", repository.fileCount())
	}
}

func TestCleanupOnlyDeletesExpiredUnfinishedOwnPath(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("cleanup payload")
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	options := defaultTestOptions(clock)
	options.CleanupGrace = time.Nanosecond
	service := mustTestService(t, repository, objectStore, clock, options)

	completedRequest := testRequest(owner, payload)
	completedRequest.ID = "00000000-0000-4000-8000-000000000001"
	completedStart, err := service.Start(context.Background(), completedRequest)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(completedStart.Session.StoragePath, payload, completedRequest.MIMEType, "etag")
	if _, err := service.Complete(context.Background(), owner, completedRequest.ID, nil, nil); err != nil {
		t.Fatal(err)
	}

	expiredRequest := testRequest(owner, []byte("other payload"))
	expiredRequest.ID = "00000000-0000-4000-8000-000000000002"
	expiredRequest.ExpiresAt = clock.Now().Add(time.Second)
	expiredStart, err := service.Start(context.Background(), expiredRequest)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(expiredStart.Session.StoragePath, []byte("partial"), expiredRequest.MIMEType, "etag")
	clock.advance(2 * time.Second)
	removed, err := service.CleanupExpired(context.Background(), clock.Now().Add(time.Second), 10)
	if err != nil || removed != 1 {
		t.Fatalf("CleanupExpired() = %d, %v", removed, err)
	}
	objectStore.mu.Lock()
	defer objectStore.mu.Unlock()
	if _, exists := objectStore.objects[completedStart.Session.StoragePath]; !exists {
		t.Fatal("cleanup deleted a completed shared object")
	}
	if _, exists := objectStore.objects[expiredStart.Session.StoragePath]; exists {
		t.Fatal("cleanup kept expired temporary object")
	}
	expiredSession, err := service.Get(context.Background(), owner, expiredRequest.ID)
	if err != nil || expiredSession.State != StateExpired || expiredSession.FileID != nil {
		t.Fatalf("expired session = %#v, %v", expiredSession, err)
	}
}

func TestUseVerifiedObjectRepointsOnlyCompletedFilePath(t *testing.T) {
	service, repository, objectStore, request, file := completedUploadFixture(t)
	originalSessionPath := file.StoragePath
	canonicalPath, err := storage.GenerateFileStoragePath(request.Purpose, testOwner("org-b", "user-b"), ".jpg")
	if err != nil {
		t.Fatal(err)
	}
	verified := VerifiedObject{SizeBytes: file.Size, SHA256: request.SHA256, MIMEType: file.MIMEType, StoragePath: canonicalPath}
	updated, err := service.UseVerifiedObject(context.Background(), request.Owner, request.ID, verified)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != file.ID || updated.StoragePath != canonicalPath {
		t.Fatalf("updated file = %#v", updated)
	}
	session, err := service.Get(context.Background(), request.Owner, request.ID)
	if err != nil || session.StoragePath != originalSessionPath || session.State != StateCompleted {
		t.Fatalf("session path changed = %#v, %v", session, err)
	}
	again, err := service.UseVerifiedObject(context.Background(), request.Owner, request.ID, verified)
	if err != nil || again.ID != file.ID || again.StoragePath != canonicalPath {
		t.Fatalf("idempotent UseVerifiedObject() = %#v, %v", again, err)
	}
	if count := repository.fileCount(); count != 1 {
		t.Fatalf("file count = %d, want 1", count)
	}
	objectStore.mu.Lock()
	deleted := append([]string(nil), objectStore.deleted...)
	objectStore.mu.Unlock()
	if len(deleted) != 0 {
		t.Fatalf("UseVerifiedObject() touched objects: %v", deleted)
	}
}

func TestUseVerifiedObjectRejectsOwnerStateAndMetadataMismatch(t *testing.T) {
	service, _, _, request, file := completedUploadFixture(t)
	validPath := request.Purpose + "/20261105/canonical.bin"
	base := VerifiedObject{SizeBytes: file.Size, SHA256: request.SHA256, MIMEType: file.MIMEType, StoragePath: validPath}
	if _, err := service.UseVerifiedObject(context.Background(), testOwner("org-b", "user-b"), request.ID, base); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner UseVerifiedObject() error = %v, want ErrNotFound", err)
	}
	tests := []struct {
		name   string
		mutate func(*VerifiedObject)
	}{
		{name: "wrong size", mutate: func(value *VerifiedObject) { value.SizeBytes++ }},
		{name: "wrong digest", mutate: func(value *VerifiedObject) { value.SHA256 = strings.Repeat("0", 64) }},
		{name: "uppercase digest", mutate: func(value *VerifiedObject) { value.SHA256 = strings.ToUpper(value.SHA256) }},
		{name: "wrong MIME", mutate: func(value *VerifiedObject) { value.MIMEType = "text/plain" }},
		{name: "wrong purpose", mutate: func(value *VerifiedObject) { value.StoragePath = "other-purpose/20261105/file.bin" }},
		{name: "traversal", mutate: func(value *VerifiedObject) { value.StoragePath = request.Purpose + "/20261105/../file.bin" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verified := base
			test.mutate(&verified)
			if _, err := service.UseVerifiedObject(context.Background(), request.Owner, request.ID, verified); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("UseVerifiedObject() error = %v, want ErrIntegrity", err)
			}
		})
	}

	incompleteRequest := testRequest(request.Owner, []byte("incomplete"))
	incompleteRequest.ID = "00000000-0000-4000-8000-000000000021"
	if _, err := service.Start(context.Background(), incompleteRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UseVerifiedObject(context.Background(), request.Owner, incompleteRequest.ID, base); !errors.Is(err, ErrConflict) {
		t.Fatalf("incomplete UseVerifiedObject() error = %v, want ErrConflict", err)
	}
}

func TestUseVerifiedObjectRetriesFileCASFailure(t *testing.T) {
	service, repository, _, request, file := completedUploadFixture(t)
	repository.updateFilePathFailures = 1
	canonicalPath := request.Purpose + "/20261105/retry.bin"
	verified := VerifiedObject{SizeBytes: file.Size, SHA256: request.SHA256, MIMEType: file.MIMEType, StoragePath: canonicalPath}
	if _, err := service.UseVerifiedObject(context.Background(), request.Owner, request.ID, verified); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first UseVerifiedObject() error = %v, want ErrUnavailable", err)
	}
	unchanged, err := repository.GetFile(context.Background(), request.Owner, file.ID)
	if err != nil || unchanged.StoragePath != file.StoragePath {
		t.Fatalf("file changed after failed update = %#v, %v", unchanged, err)
	}
	updated, err := service.UseVerifiedObject(context.Background(), request.Owner, request.ID, verified)
	if err != nil || updated.StoragePath != canonicalPath {
		t.Fatalf("retry UseVerifiedObject() = %#v, %v", updated, err)
	}
}

func TestUseVerifiedObjectConcurrentDifferentPathsConflict(t *testing.T) {
	service, repository, _, request, file := completedUploadFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	repository.updateFileHolds, repository.updateFileEntered, repository.updateFileRelease = 2, entered, release
	paths := []string{
		request.Purpose + "/20261105/concurrent-a.bin",
		request.Purpose + "/20261105/concurrent-b.bin",
	}
	start := make(chan struct{})
	results := make(chan error, len(paths))
	for _, storagePath := range paths {
		storagePath := storagePath
		go func() {
			<-start
			_, err := service.UseVerifiedObject(context.Background(), request.Owner, request.ID, VerifiedObject{
				SizeBytes: file.Size, SHA256: request.SHA256, MIMEType: file.MIMEType, StoragePath: storagePath,
			})
			results <- err
		}()
	}
	close(start)
	<-entered
	close(release)
	successes, conflicts := 0, 0
	for range paths {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("concurrent UseVerifiedObject() error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent results = success:%d conflict:%d", successes, conflicts)
	}
	finalFile, err := repository.GetFile(context.Background(), request.Owner, file.ID)
	if err != nil || (finalFile.StoragePath != paths[0] && finalFile.StoragePath != paths[1]) {
		t.Fatalf("final concurrent path = %#v, %v", finalFile, err)
	}
}

func TestAbortingLeaseCannotBeReclaimedByComplete(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("slow abort payload")
	request := testRequest(owner, payload)
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	service := mustTestService(t, repository, objectStore, clock, defaultTestOptions(clock))
	started, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(started.Session.StoragePath, payload, request.MIMEType, "etag")
	entered, release := make(chan struct{}), make(chan struct{})
	objectStore.deleteEntered, objectStore.deleteRelease = entered, release
	abortDone := make(chan error, 1)
	go func() { abortDone <- service.Abort(context.Background(), owner, request.ID) }()
	<-entered
	clock.advance(2 * time.Minute)
	if _, err := service.Complete(context.Background(), owner, request.ID, nil, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("Complete() during expired aborting lease error = %v, want ErrConflict", err)
	}
	if repository.fileCount() != 0 {
		t.Fatal("Complete registered a file while abort was still running")
	}
	close(release)
	if err := <-abortDone; !errors.Is(err, ErrConflict) {
		t.Fatalf("slow Abort() after lease expiry error = %v, want ErrConflict", err)
	}
	if err := service.Abort(context.Background(), owner, request.ID); err != nil {
		t.Fatalf("retry Abort() after lease expiry = %v", err)
	}
	session, err := service.Get(context.Background(), owner, request.ID)
	if err != nil || session.State != StateAborted {
		t.Fatalf("aborted session = %#v, %v", session, err)
	}
}

func TestAbortFailureKeepsAbortingLeaseForRetry(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("abort retry payload")
	request := testRequest(owner, payload)
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	service := mustTestService(t, repository, objectStore, clock, defaultTestOptions(clock))
	started, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(started.Session.StoragePath, payload, request.MIMEType, "etag")
	objectStore.deleteErr = errors.New("temporary delete failure")
	if err := service.Abort(context.Background(), owner, request.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Abort() delete failure = %v, want ErrUnavailable", err)
	}
	session, err := service.Get(context.Background(), owner, request.ID)
	if err != nil || session.State != StateAborting || session.LeaseToken == "" {
		t.Fatalf("session after failed abort = %#v, %v", session, err)
	}
	if err := service.Abort(context.Background(), owner, request.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("Abort() while lease busy = %v, want ErrConflict", err)
	}
	objectStore.deleteErr = nil
	clock.advance(2 * time.Minute)
	if err := service.Abort(context.Background(), owner, request.ID); err != nil {
		t.Fatalf("Abort() after lease expiry = %v", err)
	}
}

func TestAbortRetryTreatsTypedNoSuchUploadAsAlreadyAborted(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	request := testRequest(owner, []byte("multipart abort retry"))
	request.AllowMultipart = true
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	repository.finishFailures = 1
	service := mustTestService(t, repository, objectStore, clock, Options{
		MultipartThreshold: 8, PartSize: 16, CompletionTimeout: time.Minute, CleanupGrace: time.Hour,
	})
	if _, err := service.Start(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := service.Abort(context.Background(), owner, request.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first Abort() error = %v, want ErrUnavailable", err)
	}
	session, err := service.Get(context.Background(), owner, request.ID)
	if err != nil || session.State != StateAborting {
		t.Fatalf("session after Finish failure = %#v, %v", session, err)
	}
	clock.advance(2 * time.Minute)
	objectStore.abortMultipartErr = typedErrorCode{code: "NoSuchUpload", message: "provider upload missing"}
	if err := service.Abort(context.Background(), owner, request.ID); err != nil {
		t.Fatalf("retry Abort() with NoSuchUpload = %v", err)
	}
	session, err = service.Get(context.Background(), owner, request.ID)
	if err != nil || session.State != StateAborted {
		t.Fatalf("session after NoSuchUpload retry = %#v, %v", session, err)
	}
}

func TestAbortDoesNotTreatOtherTypedCodesAsAlreadyAborted(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	request := testRequest(owner, []byte("multipart abort denied"))
	request.AllowMultipart = true
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	service := mustTestService(t, repository, objectStore, clock, Options{
		MultipartThreshold: 8, PartSize: 16, CompletionTimeout: time.Minute, CleanupGrace: time.Hour,
	})
	if _, err := service.Start(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	objectStore.abortMultipartErr = typedErrorCode{code: "AccessDenied", message: "NoSuchUpload text must not match"}
	if err := service.Abort(context.Background(), owner, request.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Abort() with AccessDenied error = %v, want ErrUnavailable", err)
	}
	session, err := service.Get(context.Background(), owner, request.ID)
	if err != nil || session.State != StateAborting {
		t.Fatalf("session after AccessDenied = %#v, %v", session, err)
	}
}

type typedErrorCode struct {
	code    string
	message string
}

func (err typedErrorCode) Error() string     { return err.message }
func (err typedErrorCode) ErrorCode() string { return err.code }

func TestAbortObjectIOUsesLeaseBoundedContext(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("bounded abort payload")
	request := testRequest(owner, payload)
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	options := defaultTestOptions(clock)
	options.CompletionTimeout = 20 * time.Millisecond
	service := mustTestService(t, repository, objectStore, clock, options)
	started, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(started.Session.StoragePath, payload, request.MIMEType, "etag")
	objectStore.waitDeleteContext = true
	if err := service.Abort(context.Background(), owner, request.ID); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Abort() timeout error = %v", err)
	}
	session, err := service.Get(context.Background(), owner, request.ID)
	if err != nil || session.State != StateAborting {
		t.Fatalf("session after timed out abort = %#v, %v", session, err)
	}
}

func TestRegisterExistingIsOwnerScopedAndIdempotent(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	service := mustTestService(t, repository, objectStore, clock, defaultTestOptions(clock))
	payload := []byte("same content")
	ownerA := testOwner("org-a", "user-a")
	ownerB := testOwner("org-b", "user-b")
	requestA := testRequest(ownerA, payload)
	requestA.ID = "00000000-0000-4000-8000-000000000011"
	requestB := testRequest(ownerB, payload)
	requestB.ID = "00000000-0000-4000-8000-000000000012"
	pathA, err := storage.GenerateFileStoragePath(requestA.Purpose, ownerA, requestA.FileExt)
	if err != nil {
		t.Fatal(err)
	}
	pathB, err := storage.GenerateFileStoragePath(requestB.Purpose, ownerB, requestB.FileExt)
	if err != nil {
		t.Fatal(err)
	}
	verifiedA := VerifiedObject{SizeBytes: requestA.SizeBytes, SHA256: requestA.SHA256, MIMEType: requestA.MIMEType, StoragePath: pathA}
	verifiedB := VerifiedObject{SizeBytes: requestB.SizeBytes, SHA256: requestB.SHA256, MIMEType: requestB.MIMEType, StoragePath: pathB}
	fileA, err := service.RegisterExisting(context.Background(), requestA, verifiedA)
	if err != nil {
		t.Fatal(err)
	}
	fileAAgain, err := service.RegisterExisting(context.Background(), requestA, verifiedA)
	if err != nil || fileAAgain.ID != fileA.ID {
		t.Fatalf("idempotent RegisterExisting() = %#v, %v", fileAAgain, err)
	}
	sameMetadata := requestA
	sameMetadata.ExpiresAt = clock.Now().Add(48 * time.Hour)
	sameAgain, err := service.RegisterExisting(context.Background(), sameMetadata, verifiedA)
	if err != nil || sameAgain.ID != fileA.ID {
		t.Fatalf("RegisterExisting() ignored expiry retry = %#v, %v", sameAgain, err)
	}
	changedFilename := requestA
	changedFilename.Filename = "renamed.bin"
	if _, err := service.RegisterExisting(context.Background(), changedFilename, verifiedA); !errors.Is(err, ErrConflict) {
		t.Fatalf("RegisterExisting() changed request metadata error = %v, want ErrConflict", err)
	}
	changedVerified := verifiedA
	changedVerified.StoragePath += ".normalized.bin"
	if _, err := service.RegisterExisting(context.Background(), requestA, changedVerified); !errors.Is(err, ErrConflict) {
		t.Fatalf("RegisterExisting() changed attested metadata error = %v, want ErrConflict", err)
	}
	fileB, err := service.RegisterExisting(context.Background(), requestB, verifiedB)
	if err != nil {
		t.Fatal(err)
	}
	if fileA.ID == fileB.ID || fileA.OrganizationID != ownerA.OrganizationID || fileB.UserID != ownerB.UserID {
		t.Fatalf("owner-specific files = %#v / %#v", fileA, fileB)
	}
	if _, err := service.Get(context.Background(), ownerB, requestA.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner Get() error = %v, want ErrNotFound", err)
	}
	completedSession, err := service.Get(context.Background(), ownerA, requestA.ID)
	if err != nil || completedSession.State != StateCompleted || completedSession.FileID == nil || *completedSession.FileID != fileA.ID {
		t.Fatalf("completed Get() = %#v, %v", completedSession, err)
	}
	if _, err := service.PartURLs(context.Background(), ownerB, requestA.ID, []int32{1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner PartURLs() error = %v, want ErrNotFound", err)
	}
	if _, err := service.Complete(context.Background(), ownerB, requestA.ID, nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner Complete() error = %v, want ErrNotFound", err)
	}
}

func TestTrustedAttestationCanReusePhysicalPathWithoutChangingOwner(t *testing.T) {
	ownerA := testOwner("org-a", "user-a")
	ownerB := testOwner("org-b", "user-b")
	payload := []byte("path payload")
	request := testRequest(ownerA, payload)
	pathB, err := storage.GenerateFileStoragePath(request.Purpose, ownerB, request.FileExt)
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	service := mustTestService(t, newMemoryRepository(clock), newMemoryStorage(), clock, defaultTestOptions(clock))
	file, err := service.RegisterExisting(context.Background(), request, VerifiedObject{
		SizeBytes: request.SizeBytes, SHA256: request.SHA256, MIMEType: request.MIMEType, StoragePath: pathB,
	})
	if err != nil {
		t.Fatalf("RegisterExisting(trusted shared path) error = %v", err)
	}
	if file.OrganizationID != ownerA.OrganizationID || file.UserID != ownerA.UserID || file.StoragePath != pathB {
		t.Fatalf("shared physical path changed Core owner = %#v", file)
	}
	requestB := request
	requestB.ID = "00000000-0000-4000-8000-000000000099"
	requestB.Owner = ownerB
	fileB, err := service.RegisterExisting(context.Background(), requestB, VerifiedObject{
		SizeBytes: requestB.SizeBytes, SHA256: requestB.SHA256, MIMEType: requestB.MIMEType, StoragePath: pathB,
	})
	if err != nil {
		t.Fatalf("RegisterExisting(second owner, shared path) error = %v", err)
	}
	if fileB.ID == file.ID || fileB.StoragePath != pathB || fileB.OrganizationID != ownerB.OrganizationID || fileB.UserID != ownerB.UserID {
		t.Fatalf("shared path ownership = %#v / %#v", file, fileB)
	}
}

func TestTrustedAttestationStillRejectsUnsafeOrInconsistentMetadata(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("attestation payload")
	request := testRequest(owner, payload)
	validPath, err := storage.GenerateFileStoragePath(request.Purpose, owner, request.FileExt)
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	service := mustTestService(t, newMemoryRepository(clock), newMemoryStorage(), clock, defaultTestOptions(clock))
	base := VerifiedObject{SizeBytes: request.SizeBytes, SHA256: request.SHA256, MIMEType: request.MIMEType, StoragePath: validPath}
	tests := []struct {
		name   string
		mutate func(*VerifiedObject)
	}{
		{name: "empty digest", mutate: func(value *VerifiedObject) { value.SHA256 = "" }},
		{name: "uppercase digest", mutate: func(value *VerifiedObject) { value.SHA256 = strings.ToUpper(value.SHA256) }},
		{name: "wrong size", mutate: func(value *VerifiedObject) { value.SizeBytes++ }},
		{name: "invalid MIME", mutate: func(value *VerifiedObject) { value.MIMEType = "not a mime" }},
		{name: "wrong purpose", mutate: func(value *VerifiedObject) { value.StoragePath = "another-purpose/20261105/file.bin" }},
		{name: "traversal", mutate: func(value *VerifiedObject) { value.StoragePath = request.Purpose + "/20261105/../file.bin" }},
		{name: "empty path", mutate: func(value *VerifiedObject) { value.StoragePath = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verified := base
			test.mutate(&verified)
			if _, err := service.RegisterExisting(context.Background(), request, verified); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("RegisterExisting() error = %v, want ErrIntegrity", err)
			}
		})
	}
}

func TestTemporaryStorageFailureAndCancellationReleaseLease(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := []byte("temporary failure")
	request := testRequest(owner, payload)
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	service := mustTestService(t, repository, objectStore, clock, defaultTestOptions(clock))
	started, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(started.Session.StoragePath, payload, request.MIMEType, "etag")
	objectStore.headErr = errors.New("temporary head failure")
	if _, err := service.Complete(context.Background(), owner, request.ID, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Complete() head failure error = %v, want ErrUnavailable", err)
	}
	session, err := service.Get(context.Background(), owner, request.ID)
	if err != nil || session.State != StateActive || session.LeaseToken != "" {
		t.Fatalf("session after failure = %#v, %v", session, err)
	}
	objectStore.headErr = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Complete(ctx, owner, request.ID, nil, nil); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Complete(canceled) error = %v", err)
	}
}

func TestPartURLsValidateBatchAndOwner(t *testing.T) {
	owner := testOwner("org-a", "user-a")
	payload := bytes.Repeat([]byte{1}, 48)
	request := testRequest(owner, payload)
	request.AllowMultipart = true
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	service := mustTestService(t, repository, objectStore, clock, Options{
		MultipartThreshold: 16,
		PartSize:           16,
		CompletionTimeout:  time.Minute,
		CleanupGrace:       time.Hour,
	})
	if _, err := service.Start(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	urls, err := service.PartURLs(context.Background(), owner, request.ID, []int32{2, 1})
	if err != nil || len(urls) != 2 || urls[0].PartNumber != 2 || urls[0].UploadURL == "" {
		t.Fatalf("PartURLs() = %#v, %v", urls, err)
	}
	for _, numbers := range [][]int32{{}, {0}, {4}, {1, 1}} {
		if _, err := service.PartURLs(context.Background(), owner, request.ID, numbers); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("PartURLs(%v) error = %v", numbers, err)
		}
	}
}

type ownerKey struct {
	organizationID string
	userID         string
}

func ownerKeyOf(member identity.Member) ownerKey {
	return ownerKey{organizationID: member.OrganizationID, userID: member.UserID}
}

type fileKey struct {
	owner ownerKey
	id    uint
}

type sessionKey struct {
	owner ownerKey
	id    string
}

type memoryRepository struct {
	mu                     sync.Mutex
	clock                  *fakeClock
	sessions               map[sessionKey]*Session
	files                  map[fileKey]*storage.CoreFileInfo
	nextFileID             uint
	createErr              error
	finalizeFailures       int
	updateFilePathFailures int
	finishFailures         int
	getFileHolds           int
	getFileEntered         chan struct{}
	getFileRelease         chan struct{}
	updateFileHolds        int
	updateFileEntered      chan struct{}
	updateFileRelease      chan struct{}
}

func newMemoryRepository(clock *fakeClock) *memoryRepository {
	return &memoryRepository{clock: clock, sessions: map[sessionKey]*Session{}, files: map[fileKey]*storage.CoreFileInfo{}}
}

func (repository *memoryRepository) CreateSession(_ context.Context, session *Session) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.createErr != nil {
		return repository.createErr
	}
	key := sessionKey{owner: ownerKeyOf(identity.Member{OrganizationID: session.OrganizationID, UserID: session.UserID}), id: session.ID}
	if _, exists := repository.sessions[key]; exists {
		return ErrConflict
	}
	repository.sessions[key] = cloneSession(session)
	return nil
}

func (repository *memoryRepository) GetSession(_ context.Context, owner identity.Member, id string) (*Session, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	session, exists := repository.sessions[sessionKey{owner: ownerKeyOf(owner), id: id}]
	if !exists {
		return nil, ErrNotFound
	}
	return cloneSession(session), nil
}

func (repository *memoryRepository) ClaimLease(_ context.Context, owner identity.Member, id string, state State, token string, now, until time.Time) (*Session, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	session, exists := repository.sessions[sessionKey{owner: ownerKeyOf(owner), id: id}]
	if !exists {
		return nil, ErrNotFound
	}
	expiredLease := session.LeaseExpiresAt != nil && !now.Before(*session.LeaseExpiresAt)
	claimable := session.State == StateActive
	switch state {
	case StateCompleting:
		claimable = claimable || (session.State == StateCompleting && expiredLease)
	case StateAborting:
		claimable = claimable || ((session.State == StateCompleting || session.State == StateAborting) && expiredLease)
	}
	if !claimable {
		return nil, ErrConflict
	}
	session.State, session.LeaseToken, session.LeaseExpiresAt = state, token, timePointer(until)
	session.UpdatedAt = now
	return cloneSession(session), nil
}

func (repository *memoryRepository) ReleaseLease(_ context.Context, owner identity.Member, id, token string) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	session, exists := repository.sessions[sessionKey{owner: ownerKeyOf(owner), id: id}]
	if !exists {
		return ErrNotFound
	}
	if session.LeaseToken != token || session.State != StateCompleting {
		return ErrConflict
	}
	session.State, session.LeaseToken, session.LeaseExpiresAt = StateActive, "", nil
	session.UpdatedAt = repository.clock.Now()
	return nil
}

func (repository *memoryRepository) Finish(_ context.Context, owner identity.Member, id, token string, state State, now time.Time) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	session, exists := repository.sessions[sessionKey{owner: ownerKeyOf(owner), id: id}]
	if !exists {
		return ErrNotFound
	}
	if session.LeaseToken != token || isTerminalState(session.State) || (session.LeaseExpiresAt != nil && !now.Before(*session.LeaseExpiresAt)) {
		return ErrConflict
	}
	if repository.finishFailures > 0 {
		repository.finishFailures--
		return errors.New("temporary finish failure")
	}
	session.State, session.LeaseToken, session.LeaseExpiresAt, session.UpdatedAt = state, "", nil, now
	return nil
}

func (repository *memoryRepository) FinalizeComplete(_ context.Context, owner identity.Member, id, token string, now time.Time, file *storage.CoreFileInfo) (*storage.CoreFileInfo, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	session, exists := repository.sessions[sessionKey{owner: ownerKeyOf(owner), id: id}]
	if !exists {
		return nil, ErrNotFound
	}
	if session.State == StateCompleted && session.FileID != nil {
		return cloneFile(repository.files[fileKey{owner: ownerKeyOf(owner), id: *session.FileID}]), nil
	}
	if session.State != StateCompleting || session.LeaseToken != token || session.LeaseExpiresAt == nil || !now.Before(*session.LeaseExpiresAt) {
		return nil, ErrConflict
	}
	if repository.finalizeFailures > 0 {
		repository.finalizeFailures--
		return nil, errors.New("temporary finalize failure")
	}
	repository.nextFileID++
	file.ID = repository.nextFileID
	stored := cloneFile(file)
	repository.files[fileKey{owner: ownerKeyOf(owner), id: file.ID}] = stored
	session.State, session.LeaseToken, session.LeaseExpiresAt = StateCompleted, "", nil
	session.FileID, session.UpdatedAt = &file.ID, now
	return cloneFile(stored), nil
}

func (repository *memoryRepository) RegisterExisting(_ context.Context, session *Session, file *storage.CoreFileInfo) (*storage.CoreFileInfo, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := sessionKey{owner: ownerKeyOf(identity.Member{OrganizationID: session.OrganizationID, UserID: session.UserID}), id: session.ID}
	if existing, exists := repository.sessions[key]; exists {
		if existing.State != StateCompleted || existing.FileID == nil {
			return nil, ErrConflict
		}
		return cloneFile(repository.files[fileKey{owner: key.owner, id: *existing.FileID}]), nil
	}
	repository.nextFileID++
	file.ID = repository.nextFileID
	stored := cloneFile(file)
	repository.files[fileKey{owner: key.owner, id: file.ID}] = stored
	session.State, session.FileID = StateCompleted, &file.ID
	repository.sessions[key] = cloneSession(session)
	return cloneFile(stored), nil
}

func (repository *memoryRepository) UpdateFilePath(_ context.Context, owner identity.Member, id string, fileID uint, expectedPath, storagePath string) (*storage.CoreFileInfo, error) {
	for {
		repository.mu.Lock()
		session, exists := repository.sessions[sessionKey{owner: ownerKeyOf(owner), id: id}]
		if !exists {
			repository.mu.Unlock()
			return nil, ErrNotFound
		}
		if session.State != StateCompleted || session.FileID == nil || *session.FileID != fileID {
			repository.mu.Unlock()
			return nil, ErrConflict
		}
		file, exists := repository.files[fileKey{owner: ownerKeyOf(owner), id: fileID}]
		if !exists {
			repository.mu.Unlock()
			return nil, ErrConflict
		}
		if file.StoragePath == storagePath {
			cloned := cloneFile(file)
			repository.mu.Unlock()
			return cloned, nil
		}
		if file.StoragePath != expectedPath {
			repository.mu.Unlock()
			return nil, ErrConflict
		}
		if repository.updateFileHolds > 0 {
			repository.updateFileHolds--
			if repository.updateFileHolds == 0 {
				close(repository.updateFileEntered)
			}
			release := repository.updateFileRelease
			repository.mu.Unlock()
			<-release
			continue
		}
		if repository.updateFilePathFailures > 0 {
			repository.updateFilePathFailures--
			repository.mu.Unlock()
			return nil, errors.New("temporary file path update failure")
		}
		file.StoragePath = storagePath
		cloned := cloneFile(file)
		repository.mu.Unlock()
		return cloned, nil
	}
}

func (repository *memoryRepository) ListExpired(_ context.Context, before time.Time, limit int) ([]*Session, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	result := make([]*Session, 0)
	for _, session := range repository.sessions {
		if isTerminalState(session.State) || !session.ExpiresAt.Before(before) {
			continue
		}
		if session.State != StateActive && (session.LeaseExpiresAt == nil || repository.clock.Now().Before(*session.LeaseExpiresAt)) {
			continue
		}
		result = append(result, cloneSession(session))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (repository *memoryRepository) GetFile(_ context.Context, owner identity.Member, id uint) (*storage.CoreFileInfo, error) {
	repository.mu.Lock()
	if repository.getFileHolds > 0 {
		repository.getFileHolds--
		if repository.getFileHolds == 0 {
			close(repository.getFileEntered)
		}
		release := repository.getFileRelease
		repository.mu.Unlock()
		<-release
		repository.mu.Lock()
	}
	file, exists := repository.files[fileKey{owner: ownerKeyOf(owner), id: id}]
	if !exists {
		repository.mu.Unlock()
		return nil, ErrNotFound
	}
	cloned := cloneFile(file)
	repository.mu.Unlock()
	return cloned, nil
}

func (repository *memoryRepository) fileCount() int {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return len(repository.files)
}

type memoryStorage struct {
	mu                     sync.Mutex
	objects                map[string][]byte
	contentTypes           map[string]string
	etags                  map[string]string
	uploads                map[string][]storage.MultipartUploadPart
	nextUpload             int
	headErr                error
	readErr                error
	failMultipartComplete  bool
	createMultipartCalls   int
	completeMultipartCalls int
	abortMultipartCalls    int
	abortMultipartErr      error
	deleted                []string
	deleteErr              error
	deleteEntered          chan struct{}
	deleteRelease          chan struct{}
	waitDeleteContext      bool
}

func newMemoryStorage() *memoryStorage {
	return &memoryStorage{objects: map[string][]byte{}, contentTypes: map[string]string{}, etags: map[string]string{}, uploads: map[string][]storage.MultipartUploadPart{}}
}

func (objectStore *memoryStorage) GetPresignedURL(_ context.Context, method, storagePath string) (string, error) {
	return "https://storage.invalid/" + strings.ToLower(method) + "/" + storagePath, nil
}

func (objectStore *memoryStorage) HeadFile(_ context.Context, storagePath string) (*storage.FileMetadata, error) {
	objectStore.mu.Lock()
	defer objectStore.mu.Unlock()
	if objectStore.headErr != nil {
		return nil, objectStore.headErr
	}
	payload, exists := objectStore.objects[storagePath]
	if !exists {
		return nil, errors.New("object not found")
	}
	return &storage.FileMetadata{ContentLength: int64(len(payload)), ContentType: objectStore.contentTypes[storagePath], ETag: objectStore.etags[storagePath]}, nil
}

func (objectStore *memoryStorage) ReadFile(_ context.Context, storagePath string) (io.ReadCloser, error) {
	objectStore.mu.Lock()
	defer objectStore.mu.Unlock()
	if objectStore.readErr != nil {
		return nil, objectStore.readErr
	}
	payload, exists := objectStore.objects[storagePath]
	if !exists {
		return nil, errors.New("object not found")
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), payload...))), nil
}

func (objectStore *memoryStorage) DeleteFile(ctx context.Context, storagePath string) error {
	objectStore.mu.Lock()
	objectStore.deleted = append(objectStore.deleted, storagePath)
	if objectStore.deleteEntered != nil {
		close(objectStore.deleteEntered)
		objectStore.deleteEntered = nil
	}
	release := objectStore.deleteRelease
	deleteErr := objectStore.deleteErr
	waitDeleteContext := objectStore.waitDeleteContext
	objectStore.mu.Unlock()
	if release != nil {
		<-release
	}
	if waitDeleteContext {
		<-ctx.Done()
		return ctx.Err()
	}
	if deleteErr != nil {
		return deleteErr
	}
	objectStore.mu.Lock()
	defer objectStore.mu.Unlock()
	delete(objectStore.objects, storagePath)
	delete(objectStore.contentTypes, storagePath)
	delete(objectStore.etags, storagePath)
	return nil
}

func (objectStore *memoryStorage) CreateMultipartUpload(_ context.Context, storagePath, contentType string) (string, error) {
	objectStore.mu.Lock()
	defer objectStore.mu.Unlock()
	objectStore.createMultipartCalls++
	objectStore.nextUpload++
	uploadID := "upload-" + string(rune('0'+objectStore.nextUpload))
	objectStore.uploads[uploadID] = []storage.MultipartUploadPart{{PartNumber: 1, ETag: "part-1"}, {PartNumber: 2, ETag: "part-2"}, {PartNumber: 3, ETag: "part-3"}, {PartNumber: 4, ETag: "part-4"}}
	objectStore.contentTypes[storagePath] = contentType
	return uploadID, nil
}

func (objectStore *memoryStorage) GetMultipartUploadPartPresignedURL(_ context.Context, storagePath, uploadID string, partNumber int32) (string, error) {
	if _, exists := objectStore.uploads[uploadID]; !exists {
		return "", errors.New("upload not found")
	}
	return "https://storage.invalid/part/" + storagePath + "/" + uploadID + "/" + string(rune('0'+partNumber)), nil
}

func (objectStore *memoryStorage) ListMultipartUploadParts(_ context.Context, storagePath, uploadID string) ([]storage.MultipartUploadPart, error) {
	objectStore.mu.Lock()
	defer objectStore.mu.Unlock()
	parts, exists := objectStore.uploads[uploadID]
	if !exists {
		return nil, errors.New("upload not found")
	}
	return append([]storage.MultipartUploadPart(nil), parts...), nil
}

func (objectStore *memoryStorage) CompleteMultipartUpload(_ context.Context, storagePath, uploadID string, parts map[int32]string) error {
	objectStore.mu.Lock()
	defer objectStore.mu.Unlock()
	objectStore.completeMultipartCalls++
	if objectStore.failMultipartComplete {
		return errors.New("upload already completed")
	}
	if _, exists := objectStore.uploads[uploadID]; !exists {
		return errors.New("upload not found")
	}
	if _, exists := objectStore.objects[storagePath]; !exists {
		objectStore.objects[storagePath] = nil
	}
	delete(objectStore.uploads, uploadID)
	return nil
}

func (objectStore *memoryStorage) AbortMultipartUpload(_ context.Context, storagePath, uploadID string) error {
	objectStore.mu.Lock()
	defer objectStore.mu.Unlock()
	objectStore.abortMultipartCalls++
	if objectStore.abortMultipartErr != nil {
		return objectStore.abortMultipartErr
	}
	delete(objectStore.uploads, uploadID)
	return nil
}

func (objectStore *memoryStorage) put(storagePath string, payload []byte, contentType, etag string) {
	objectStore.mu.Lock()
	defer objectStore.mu.Unlock()
	objectStore.objects[storagePath] = append([]byte(nil), payload...)
	objectStore.contentTypes[storagePath] = contentType
	objectStore.etags[storagePath] = etag
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

func mustTestService(t *testing.T, repository Repository, objectStore ObjectStorage, clock *fakeClock, options Options) *Service {
	t.Helper()
	options.Now = clock.Now
	service, err := newWithRepository(repository, objectStore, options)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func completedUploadFixture(t *testing.T) (*Service, *memoryRepository, *memoryStorage, Request, *storage.CoreFileInfo) {
	t.Helper()
	owner := testOwner("org-a", "user-a")
	payload := []byte("completed upload fixture")
	request := testRequest(owner, payload)
	clock := &fakeClock{now: time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)}
	objectStore := newMemoryStorage()
	repository := newMemoryRepository(clock)
	service := mustTestService(t, repository, objectStore, clock, defaultTestOptions(clock))
	started, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	objectStore.put(started.Session.StoragePath, payload, request.MIMEType, "etag")
	file, err := service.Complete(context.Background(), owner, request.ID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return service, repository, objectStore, request, file
}

func defaultTestOptions(clock *fakeClock) Options {
	return Options{Now: clock.Now, MultipartThreshold: 64 << 20, PartSize: 16 << 20, CompletionTimeout: time.Minute, CleanupGrace: time.Hour}
}

func testOwner(organizationID, userID string) identity.Member {
	return identity.Member{OrganizationID: organizationID, UserID: userID}
}

func testRequest(owner identity.Member, payload []byte) Request {
	return Request{
		ID: "00000000-0000-4000-8000-000000000001", Owner: owner, Purpose: "test-upload",
		Filename: "payload.bin", FileExt: ".bin", MIMEType: "application/octet-stream",
		SizeBytes: int64(len(payload)), SHA256: digestString(payload), AllowMultipart: false,
	}
}

func digestString(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func cloneSession(source *Session) *Session {
	if source == nil {
		return nil
	}
	cloned := *source
	if source.FileID != nil {
		fileID := *source.FileID
		cloned.FileID = &fileID
	}
	if source.LeaseExpiresAt != nil {
		lease := *source.LeaseExpiresAt
		cloned.LeaseExpiresAt = &lease
	}
	return &cloned
}

func cloneFile(source *storage.CoreFileInfo) *storage.CoreFileInfo {
	if source == nil {
		return nil
	}
	cloned := *source
	return &cloned
}

func timePointer(value time.Time) *time.Time { return &value }

func isTerminalState(state State) bool {
	return state == StateCompleted || state == StateAborted || state == StateExpired
}
