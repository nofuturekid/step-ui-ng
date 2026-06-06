package app

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
)

// sessionUserIDKey is the scs session key holding the logged-in user's id.
const sessionUserIDKey = "user_id"

// NewSessionManager builds an scs session manager backed by the SQLite
// `sessions` table. Cookies are HttpOnly with SameSite=Lax; Secure follows the
// deployment config (ADR-0005, FR-3). cleanupInterval evicts expired rows.
func NewSessionManager(db *sql.DB, secure bool) *scs.SessionManager {
	m := scs.New()
	m.Store = sqlite3store.NewWithCleanupInterval(db, 30*time.Minute)
	m.Lifetime = 24 * time.Hour
	m.Cookie.Name = "session"
	m.Cookie.HttpOnly = true
	m.Cookie.SameSite = http.SameSiteLaxMode
	m.Cookie.Secure = secure
	m.Cookie.Path = "/"
	return m
}
