package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	HeaderDate          = "HASP-Date"
	HeaderNonce         = "HASP-Nonce"
	AuthorizationScheme = "HASP-HMAC-SHA256"

	DefaultAllowedDateSkew = 60 * time.Second
	DefaultNonceTTL        = 5 * time.Minute
	DefaultMaxBodyBytes    = 1 << 20
)

var (
	ErrMissingDateHeader      = errors.New("missing HASP-Date header")
	ErrMissingNonceHeader     = errors.New("missing HASP-Nonce header")
	ErrMissingAuthorization   = errors.New("missing Authorization header")
	ErrMalformedDateHeader    = errors.New("malformed HASP-Date header")
	ErrMalformedNonceHeader   = errors.New("malformed HASP-Nonce header")
	ErrMalformedAuthorization = errors.New("malformed Authorization header")
	ErrDateSkewExceeded       = errors.New("request date skew exceeds limit")
	ErrInvalidSignature       = errors.New("invalid HMAC signature")
	ErrNonceReplay            = errors.New("nonce replay detected")
	ErrRequestBodyTooLarge    = errors.New("request body exceeds HMAC validation limit")
)

type ValidatorOptions struct {
	AllowedDateSkew time.Duration
	NonceTTL        time.Duration
	MaxBodyBytes    int64
	Now             func() time.Time
}

type Validator struct {
	key             []byte
	allowedDateSkew time.Duration
	maxBodyBytes    int64
	now             func() time.Time
	nonces          *nonceCache
}

type nonceCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	now     func() time.Time
	entries map[string]time.Time
}

func NewValidator(key []byte, opts ValidatorOptions) (*Validator, error) {
	if len(key) == 0 {
		return nil, errors.New("httpapi: HMAC key is required")
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = nowUTC
	}
	allowedSkew := opts.AllowedDateSkew
	if allowedSkew <= 0 {
		allowedSkew = DefaultAllowedDateSkew
	}
	nonceTTL := opts.NonceTTL
	if nonceTTL <= 0 {
		nonceTTL = DefaultNonceTTL
	}
	maxBodyBytes := opts.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}
	return &Validator{
		key:             append([]byte(nil), key...),
		allowedDateSkew: allowedSkew,
		maxBodyBytes:    maxBodyBytes,
		now:             nowFn,
		nonces: &nonceCache{
			ttl:     nonceTTL,
			now:     nowFn,
			entries: make(map[string]time.Time),
		},
	}, nil
}

func (v *Validator) Middleware(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := v.Validate(r); err != nil {
			if errors.Is(err, ErrRequestBodyTooLarge) {
				WritePublicErrorEnvelope(w, http.StatusRequestEntityTooLarge, "request_too_large", http.StatusText(http.StatusRequestEntityTooLarge))
				return
			}
			WritePublicErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "Unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func WritePublicErrorEnvelope(w http.ResponseWriter, status int, code string, title string) {
	WriteErrorEnvelope(w, status, code, title, publicErrorDetail(status, title))
}

func WriteErrorEnvelope(w http.ResponseWriter, status int, code string, title string, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"_schema": "v1",
		"error": map[string]any{
			"code":   code,
			"title":  title,
			"detail": detail,
		},
	})
}

func publicErrorDetail(status int, title string) string {
	detail := strings.TrimSpace(title)
	if detail != "" {
		return detail
	}
	return http.StatusText(status)
}

func (v *Validator) Validate(req *http.Request) error {
	if req == nil {
		return errors.New("httpapi: request is required")
	}

	dateValue := strings.TrimSpace(req.Header.Get(HeaderDate))
	if dateValue == "" {
		return ErrMissingDateHeader
	}
	requestTime, err := time.Parse(time.RFC3339Nano, dateValue)
	if err != nil {
		return ErrMalformedDateHeader
	}
	if skew := requestTime.Sub(v.now().UTC()); skew > v.allowedDateSkew || skew < -v.allowedDateSkew {
		return ErrDateSkewExceeded
	}

	nonce := strings.TrimSpace(req.Header.Get(HeaderNonce))
	if nonce == "" {
		return ErrMissingNonceHeader
	}
	if _, err := hex.DecodeString(nonce); err != nil || len(nonce) != 32 {
		return ErrMalformedNonceHeader
	}

	authHeader := strings.TrimSpace(req.Header.Get("Authorization"))
	if authHeader == "" {
		return ErrMissingAuthorization
	}
	signature, err := parseAuthorizationHeader(authHeader)
	if err != nil {
		return err
	}

	bodyHash, err := requestBodyHash(req, v.maxBodyBytes)
	if err != nil {
		return fmt.Errorf("hash request body: %w", err)
	}
	expectedSig := computeSignature(v.key, dateValue, nonce, req.Method, requestTarget(req.URL), bodyHash)
	if !hmac.Equal(signature, expectedSig) {
		return ErrInvalidSignature
	}
	if err := v.nonces.remember(nonce); err != nil {
		return err
	}
	return nil
}

func parseAuthorizationHeader(value string) ([]byte, error) {
	prefix := AuthorizationScheme + " sig="
	if !strings.HasPrefix(value, prefix) {
		return nil, ErrMalformedAuthorization
	}
	signature := strings.TrimSpace(strings.TrimPrefix(value, prefix))
	if signature == "" {
		return nil, ErrMalformedAuthorization
	}
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, ErrMalformedAuthorization
	}
	if len(decoded) != sha256.Size {
		return nil, ErrMalformedAuthorization
	}
	return decoded, nil
}

func requestBodyHash(req *http.Request, maxBytes int64) (string, error) {
	if req.Body == nil {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:]), nil
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodyBytes
	}
	if req.ContentLength > maxBytes {
		return "", ErrRequestBodyTooLarge
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, maxBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(body)) > maxBytes {
		_ = req.Body.Close()
		return "", ErrRequestBodyTooLarge
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))

	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func computeSignature(key []byte, dateValue, nonce, method, path, bodyHash string) []byte {
	mac := hmac.New(sha256.New, key)
	payload := strings.Join([]string{
		dateValue,
		nonce,
		method,
		path,
		bodyHash,
	}, "\n")
	_, _ = mac.Write([]byte(payload))
	return mac.Sum(nil)
}

func requestTarget(u *url.URL) string {
	if u == nil {
		return ""
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery == "" {
		return path
	}
	return path + "?" + u.RawQuery
}

func (c *nonceCache) remember(nonce string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now().UTC()
	cutoff := now.Add(-c.ttl)
	for seenNonce, seenAt := range c.entries {
		if seenAt.Before(cutoff) {
			delete(c.entries, seenNonce)
		}
	}
	if seenAt, ok := c.entries[nonce]; ok && !seenAt.Before(cutoff) {
		return ErrNonceReplay
	}
	c.entries[nonce] = now
	return nil
}
