// admin/handlers.go — Admin-only user management HTTP handlers.
//
// All routes require RequireAuth + RequireAdmin middleware (registered in server.go).
//
// Routes:
//   GET    /api/admin/users              → ServeListUsers
//   POST   /api/admin/users              → ServeCreateUser
//   DELETE /api/admin/users/{id}         → ServeDeleteUser
//   PUT    /api/admin/users/{id}/password → ServeResetPassword
package admin

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/TwoA2U/iocscan/auth"
)

// ── Response types ────────────────────────────────────────────────────────────

type userListItem struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	IsAdmin      bool   `json:"isAdmin"`
	MustChangePw bool   `json:"mustChangePw"`
	CreatedAt    string `json:"createdAt"`
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// ServeListUsers handles GET /api/admin/users.
// Returns all users ordered by creation time. PasswordHash is never included.
func ServeListUsers(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := auth.ListUsers(db)
		if err != nil {
			jsonErr(w, "failed to list users", http.StatusInternalServerError)
			return
		}

		items := make([]userListItem, len(users))
		for i, u := range users {
			items[i] = userListItem{
				ID:           u.ID,
				Username:     u.Username,
				IsAdmin:      u.IsAdmin,
				MustChangePw: u.MustChangePw,
				CreatedAt:    u.CreatedAt.Format("2006-01-02 15:04:05"),
			}
		}

		writeJSON(w, items)
	}
}

// ServeCreateUser handles POST /api/admin/users.
//
//	Request:  { "username": "alice", "password": "temppass", "isAdmin": false }
//	Response: { "id": "...", "username": "alice", "isAdmin": false, "mustChangePw": true }
//
// New users always have mustChangePw = true — they set their own password on first login.
func ServeCreateUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			IsAdmin  bool   `json:"isAdmin"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Username == "" || req.Password == "" {
			jsonErr(w, "username and password are required", http.StatusBadRequest)
			return
		}
		if len(req.Password) < 8 {
			jsonErr(w, "password must be at least 8 characters", http.StatusBadRequest)
			return
		}

		// CreatedBy = the admin making the request.
		creator := auth.UserFromContext(r.Context())
		creatorID := ""
		if creator != nil {
			creatorID = creator.ID
		}

		user, err := auth.CreateUser(db, req.Username, req.Password, req.IsAdmin, creatorID)
		if err != nil {
			// CreateUser returns a readable error for duplicate usernames.
			jsonErr(w, err.Error(), http.StatusConflict)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"id":           user.ID,
			"username":     user.Username,
			"isAdmin":      user.IsAdmin,
			"mustChangePw": user.MustChangePw,
		})
	}
}

// ServeDeleteUser handles DELETE /api/admin/users/{id}.
// Guards:
//   - Cannot delete yourself.
//   - Cannot delete the last admin (would lock everyone out).
func ServeDeleteUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetID := chi.URLParam(r, "id")
		if targetID == "" {
			jsonErr(w, "user id is required", http.StatusBadRequest)
			return
		}

		// Cannot delete self.
		caller := auth.UserFromContext(r.Context())
		if caller != nil && caller.ID == targetID {
			jsonErr(w, "cannot delete your own account", http.StatusBadRequest)
			return
		}

		// Cannot delete the last admin.
		target, err := auth.GetUserByID(db, targetID)
		if err != nil {
			jsonErr(w, "internal error", http.StatusInternalServerError)
			return
		}
		if target == nil {
			jsonErr(w, "user not found", http.StatusNotFound)
			return
		}
		if target.IsAdmin {
			adminCount, err := auth.CountAdmins(db)
			if err != nil {
				jsonErr(w, "internal error", http.StatusInternalServerError)
				return
			}
			if adminCount <= 1 {
				jsonErr(w, "cannot delete the last admin account", http.StatusBadRequest)
				return
			}
		}

		if err := auth.DeleteUser(db, targetID); err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, map[string]bool{"ok": true})
	}
}

// ServeResetPassword handles PUT /api/admin/users/{id}/password.
// Admin can reset any user's password without knowing the current one.
// Forces mustChangePw = true so the user sets their own on next login.
//
//	Request:  { "newPassword": "temppass123" }
//	Response: { "ok": true }
func ServeResetPassword(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetID := chi.URLParam(r, "id")
		if targetID == "" {
			jsonErr(w, "user id is required", http.StatusBadRequest)
			return
		}

		var req struct {
			NewPassword string `json:"newPassword"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if len(req.NewPassword) < 8 {
			jsonErr(w, "password must be at least 8 characters", http.StatusBadRequest)
			return
		}

		// Verify target user exists.
		user, err := auth.GetUserByID(db, targetID)
		if err != nil {
			jsonErr(w, "internal error", http.StatusInternalServerError)
			return
		}
		if user == nil {
			jsonErr(w, "user not found", http.StatusNotFound)
			return
		}

		if err := auth.UpdatePassword(db, targetID, req.NewPassword); err != nil {
			jsonErr(w, "failed to update password", http.StatusInternalServerError)
			return
		}

		// Force the user to change their password on next login.
		if err := auth.SetMustChangePw(db, targetID, true); err != nil {
			jsonErr(w, "failed to set must_change_pw", http.StatusInternalServerError)
			return
		}

		writeJSON(w, map[string]bool{"ok": true})
	}
}

// ── Response helpers ──────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
