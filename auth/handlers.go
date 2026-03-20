// auth/handlers.go — Authentication HTTP handlers.
//
// Routes (registered in server/server.go):
//   POST /auth/login            → ServeLogin
//   POST /auth/logout           → ServeLogout
//   GET  /auth/me               → ServeMe
//   POST /auth/change-password  → ServeChangePassword
//
// All handlers accept db and sm as parameters — no global state,
// fully testable without a running HTTP server.
package auth

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/alexedwards/scs/v2"
)

// ── Request / response types ──────────────────────────────────────────────────

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type userResponse struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	IsAdmin      bool   `json:"isAdmin"`
	MustChangePw bool   `json:"mustChangePw"`
}

type changePwRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// toResponse converts a User to the JSON-safe userResponse.
// PasswordHash is never included.
func toResponse(u *User) userResponse {
	return userResponse{
		ID:           u.ID,
		Username:     u.Username,
		IsAdmin:      u.IsAdmin,
		MustChangePw: u.MustChangePw,
	}
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// ServeLogin handles POST /auth/login.
//
//	Request:  { "username": "admin", "password": "admin" }
//	Response: { "id": "...", "username": "admin", "isAdmin": true, "mustChangePw": true }
//	Errors:   401 { "error": "invalid credentials" }  (same message for wrong user OR wrong pw)
func ServeLogin(db *sql.DB, sm *scs.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Username == "" || req.Password == "" {
			jsonErr(w, "username and password are required", http.StatusBadRequest)
			return
		}

		user, err := GetUserByUsername(db, req.Username)
		if err != nil {
			jsonErr(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Use the same error message whether the username doesn't exist or
		// the password is wrong — prevents username enumeration.
		if user == nil || !CheckPassword(user.PasswordHash, req.Password) {
			jsonErr(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		// Renew session token on login to prevent session fixation.
		if err := sm.RenewToken(r.Context()); err != nil {
			jsonErr(w, "session error", http.StatusInternalServerError)
			return
		}

		PutSession(r.Context(), sm, user.ID, user.IsAdmin)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(toResponse(user))
	}
}

// ServeLogout handles POST /auth/logout.
// Destroys the session regardless of whether the user is authenticated.
func ServeLogout(sm *scs.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := sm.Destroy(r.Context()); err != nil {
			jsonErr(w, "session error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}
}

// ServeMe handles GET /auth/me.
// Returns the current user if authenticated, or {"user": null} if not.
// Never returns an error — the frontend uses this to check login state on load.
func ServeMe(db *sql.DB, sm *scs.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		userID := SessionUserID(r.Context(), sm)
		if userID == "" {
			json.NewEncoder(w).Encode(map[string]any{"user": nil})
			return
		}

		user, err := GetUserByID(db, userID)
		if err != nil || user == nil {
			// Stale session — destroy it and return null.
			sm.Destroy(r.Context())
			json.NewEncoder(w).Encode(map[string]any{"user": nil})
			return
		}

		json.NewEncoder(w).Encode(map[string]any{"user": toResponse(user)})
	}
}

// ServeChangePassword handles POST /auth/change-password.
// Registered OUTSIDE RequireAuth so users with mustChangePw=true can still
// reach it. It reads the session directly to identify the user.
//
//	Request:  { "currentPassword": "admin", "newPassword": "hunter2" }
//	Response: { "ok": true }
func ServeChangePassword(db *sql.DB, sm *scs.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := SessionUserID(r.Context(), sm)
		if userID == "" {
			jsonErr(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var req changePwRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.CurrentPassword == "" || req.NewPassword == "" {
			jsonErr(w, "currentPassword and newPassword are required", http.StatusBadRequest)
			return
		}
		if len(req.NewPassword) < 8 {
			jsonErr(w, "new password must be at least 8 characters", http.StatusBadRequest)
			return
		}

		user, err := GetUserByID(db, userID)
		if err != nil || user == nil {
			jsonErr(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if !CheckPassword(user.PasswordHash, req.CurrentPassword) {
			jsonErr(w, "current password is incorrect", http.StatusUnauthorized)
			return
		}

		if err := UpdatePassword(db, userID, req.NewPassword); err != nil {
			jsonErr(w, "failed to update password", http.StatusInternalServerError)
			return
		}

		// Renew session token after password change.
		sm.RenewToken(r.Context())

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}
}
