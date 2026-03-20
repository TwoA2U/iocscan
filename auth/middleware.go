// auth/middleware.go — HTTP middleware for authentication and authorisation.
//
// Middleware chain for protected routes:
//   sessionManager.LoadAndSave  (global — loads session for every request)
//   RequireAuth                 (protected routes — 401 if no valid session)
//   RequireAdmin                (admin routes — 403 if not admin)
//
// User is attached to request context by RequireAuth so handlers can
// call UserFromContext(r.Context()) without hitting the DB again.
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/alexedwards/scs/v2"
)

// ctxKey is an unexported type for context keys in this package.
// Prevents collisions with keys from other packages.
type ctxKey int

const ctxKeyUser ctxKey = 0

// RequireAuth returns middleware that:
//  1. Reads userID from the session.
//  2. Returns HTTP 401 if no session / userID.
//  3. Loads the full User from DB and attaches it to context.
//  4. Returns HTTP 403 with {"error":"password_change_required"} if
//     mustChangePw is true — the scanner is unreachable until changed.
//     The change-password endpoint itself is public so this doesn't lock out.
func RequireAuth(db *sql.DB, sm *scs.SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := SessionUserID(r.Context(), sm)
			if userID == "" {
				jsonErr(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			user, err := GetUserByID(db, userID)
			if err != nil || user == nil {
				// Session references a deleted user — destroy the stale session.
				sm.Destroy(r.Context())
				jsonErr(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Block access to the scanner until the password is changed.
			// Allow /auth/change-password through (it's registered outside
			// this middleware group).
			if user.MustChangePw {
				jsonErr(w, "password_change_required", http.StatusForbidden)
				return
			}

			// Attach user to context for downstream handlers.
			ctx := context.WithValue(r.Context(), ctxKeyUser, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin returns middleware that allows only admin users.
// Must be used after RequireAuth (relies on user being in context).
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil || !user.IsAdmin {
			jsonErr(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// UserFromContext retrieves the authenticated User from the request context.
// Returns nil if RequireAuth middleware was not applied or user is not set.
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(ctxKeyUser).(*User)
	return u
}

// jsonErr writes a JSON error response.
func jsonErr(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
