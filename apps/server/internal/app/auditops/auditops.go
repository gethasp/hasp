package auditops

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

type VerifyResponse struct {
	ChainOK           bool       `json:"chain_ok"`
	LastVerifiedAt    *time.Time `json:"last_verified_at,omitempty"`
	TotalEntries      int        `json:"total_entries"`
	FirstCorruptionAt *int64     `json:"first_corruption_at,omitempty"`
	Error             string     `json:"error,omitempty"`
}

type ExportOptions struct {
	From time.Time
	To   time.Time
}

type ExportTrailer struct {
	Trailer bool   `json:"_trailer"`
	SHA256  string `json:"sha256"`
	HMAC    string `json:"hmac"`
	Count   int    `json:"count"`
}

var jsonMarshal = json.Marshal

func Verify(log *audit.Log, now time.Time) (VerifyResponse, error) {
	if log == nil {
		return VerifyResponse{}, errors.New("audit log is unavailable")
	}
	report, err := log.VerifyDetailed()
	if err != nil {
		return VerifyResponse{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	response := VerifyResponse{
		ChainOK:           report.OK,
		LastVerifiedAt:    &now,
		TotalEntries:      report.TotalEntries,
		FirstCorruptionAt: report.FirstCorruptionAt,
	}
	if !report.OK && report.Err != nil {
		response.Error = report.Err.Error()
	}
	return response, nil
}

func ExportNDJSON(w io.Writer, events []audit.Event, opts ExportOptions, trailerKey []byte) (ExportTrailer, error) {
	if len(trailerKey) != sha256.Size {
		return ExportTrailer{}, fmt.Errorf("audit export trailer key must be %d bytes", sha256.Size)
	}
	hash := sha256.New()
	multi := io.MultiWriter(w, hash)
	count := 0
	for _, event := range events {
		if !opts.From.IsZero() && event.Timestamp.Before(opts.From) {
			continue
		}
		if !opts.To.IsZero() && event.Timestamp.After(opts.To) {
			continue
		}
		line, err := jsonMarshal(event)
		if err != nil {
			return ExportTrailer{}, err
		}
		if _, err := multi.Write(append(line, '\n')); err != nil {
			return ExportTrailer{}, err
		}
		count++
	}
	sum := hash.Sum(nil)
	mac := hmac.New(sha256.New, trailerKey)
	_, _ = mac.Write(sum)
	trailer := ExportTrailer{
		Trailer: true,
		SHA256:  hex.EncodeToString(sum),
		HMAC:    hex.EncodeToString(mac.Sum(nil)),
		Count:   count,
	}
	line, err := jsonMarshal(trailer)
	if err != nil {
		return ExportTrailer{}, err
	}
	if _, err := w.Write(append(line, '\n')); err != nil {
		return ExportTrailer{}, err
	}
	return trailer, nil
}
