package fileupload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"strings"
)

func defaultVerifier(ctx context.Context, session *Session, objectStorage ObjectStorage) (VerifiedObject, error) {
	if session == nil || objectStorage == nil {
		return VerifiedObject{}, fmt.Errorf("%w: verifier dependencies are missing", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return VerifiedObject{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	metadata, err := objectStorage.HeadFile(ctx, session.StoragePath)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return VerifiedObject{}, fmt.Errorf("%w: %w", ErrUnavailable, ctxErr)
		}
		return VerifiedObject{}, fmt.Errorf("%w: inspect uploaded object", ErrUnavailable)
	}
	if metadata == nil || metadata.ContentLength != session.SizeBytes {
		return VerifiedObject{}, fmt.Errorf("%w: stored size mismatch", ErrIntegrity)
	}
	if !mimeEqual(metadata.ContentType, session.MIMEType) {
		return VerifiedObject{}, fmt.Errorf("%w: stored MIME mismatch", ErrIntegrity)
	}
	reader, err := objectStorage.ReadFile(ctx, session.StoragePath)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return VerifiedObject{}, fmt.Errorf("%w: %w", ErrUnavailable, ctxErr)
		}
		return VerifiedObject{}, fmt.Errorf("%w: read uploaded object", ErrUnavailable)
	}
	if reader == nil {
		return VerifiedObject{}, fmt.Errorf("%w: uploaded object reader is missing", ErrUnavailable)
	}
	digest := sha256.New()
	written, copyErr := io.Copy(digest, io.LimitReader(reader, session.SizeBytes+1))
	closeErr := reader.Close()
	if copyErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return VerifiedObject{}, fmt.Errorf("%w: %w", ErrUnavailable, ctxErr)
		}
		return VerifiedObject{}, fmt.Errorf("%w: stream uploaded object", ErrUnavailable)
	}
	if closeErr != nil {
		return VerifiedObject{}, fmt.Errorf("%w: close uploaded object", ErrUnavailable)
	}
	if written != session.SizeBytes {
		return VerifiedObject{}, fmt.Errorf("%w: streamed size mismatch", ErrIntegrity)
	}
	sha256Value := hex.EncodeToString(digest.Sum(nil))
	if session.SHA256 != "" && sha256Value != session.SHA256 {
		return VerifiedObject{}, fmt.Errorf("%w: streamed SHA256 mismatch", ErrIntegrity)
	}
	return VerifiedObject{
		SizeBytes: written, SHA256: sha256Value, MIMEType: session.MIMEType,
		StoragePath: session.StoragePath, ETag: metadata.ETag,
	}, nil
}

func canonicalMIME(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("invalid MIME type")
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return "", err
	}
	return strings.ToLower(mediaType), nil
}

func mimeEqual(left, right string) bool {
	leftType, leftErr := canonicalMIME(left)
	rightType, rightErr := canonicalMIME(right)
	return leftErr == nil && rightErr == nil && leftType == rightType
}
