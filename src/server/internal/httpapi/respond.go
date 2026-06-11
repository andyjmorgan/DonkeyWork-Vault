package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/service"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func decodeJSON(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

// writeServiceError maps a domain error to the right HTTP status; returns true if it handled one.
func writeServiceError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var ve service.ValidationError
	var ae service.OAuthAuthorizationError
	var re service.OAuthRefreshError
	switch {
	case errors.As(err, &ve):
		writeError(w, http.StatusBadRequest, ve.Message)
	case errors.As(err, &ae):
		writeError(w, http.StatusBadRequest, ae.Message)
	case errors.As(err, &re):
		writeError(w, http.StatusBadGateway, re.Message)
	default:
		writeError(w, http.StatusInternalServerError, "internal error")
	}
	return true
}

func uuidParam(s string) (uuid.UUID, bool) {
	id, err := uuid.Parse(s)
	return id, err == nil
}
