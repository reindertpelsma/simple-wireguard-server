package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const (
	smallJSONBodyLimit  int64 = 16 << 10
	mediumJSONBodyLimit int64 = 128 << 10
	largeJSONBodyLimit  int64 = 1 << 20
)

func decodeJSONRequest(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) bool {
	if maxBytes <= 0 {
		maxBytes = mediumJSONBodyLimit
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		writeJSONDecodeError(w, err)
		return false
	}
	if err := ensureJSONEOF(dec); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return false
	}
	return true
}

func decodeOptionalJSONRequest(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) bool {
	if maxBytes <= 0 {
		maxBytes = mediumJSONBodyLimit
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return true
		}
		writeJSONDecodeError(w, err)
		return false
	}
	if err := ensureJSONEOF(dec); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return false
	}
	return true
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return io.ErrUnexpectedEOF
}

func writeJSONDecodeError(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	switch {
	case errors.As(err, &maxErr):
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
	case strings.Contains(strings.ToLower(err.Error()), "http: request body too large"):
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
	default:
		http.Error(w, "Invalid request", http.StatusBadRequest)
	}
}
