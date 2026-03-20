// auth/session.go — Session manager setup and session helpers.
//
// Uses alexedwards/scs v2 with a SQLite backend so sessions survive
// server restarts. The sessions table is created by utils.InitDB().
//
// Public API:
//   NewSessionManager(db)          *scs.SessionManager
//   SessionUserID(ctx)             string
//   SessionIsAdmin(ctx)            bool
//   PutSession(ctx, sm, userID, isAdmin)
//   DestroySession(ctx, sm)        error
package auth

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
)

const (
	sessionKeyUserID  = "userID"
	sessionKeyIsAdmin = "isAdmin"
)

// NewSessionManager creates and configures the scs session manager.
// Must be called once at startup and the returned manager used for all
// session operations and as middleware.
func NewSessionManager(db *sql.DB) *scs.SessionManager {
	sm := scs.New()
	sm.Store = sqlite3store.New(db)

	// Sessions live for 24 hours of inactivity; absolute max is 7 days.
	sm.Lifetime = 7 * 24 * time.Hour
	sm.IdleTimeout = 24 * time.Hour

	// Cookie settings.
	sm.Cookie.Name = "iocscan_session"
	sm.Cookie.HttpOnly = true
	sm.Cookie.SameSite = http.SameSiteLaxMode
	sm.Cookie.Secure = false // set true when serving over HTTPS
	sm.Cookie.Persist = true // survive browser close

	return sm
}

// PutSession writes userID and isAdmin into the current session.
// Call after a successful login.
func PutSession(ctx context.Context, sm *scs.SessionManager, userID string, isAdmin bool) {
	sm.Put(ctx, sessionKeyUserID, userID)
	sm.Put(ctx, sessionKeyIsAdmin, isAdmin)
}

// SessionUserID returns the userID stored in the current session, or "".
func SessionUserID(ctx context.Context, sm *scs.SessionManager) string {
	return sm.GetString(ctx, sessionKeyUserID)
}

// SessionIsAdmin returns the isAdmin flag stored in the current session.
func SessionIsAdmin(ctx context.Context, sm *scs.SessionManager) bool {
	return sm.GetBool(ctx, sessionKeyIsAdmin)
}
