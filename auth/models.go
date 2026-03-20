// auth/models.go — User model and database operations.
//
// All functions accept a *sql.DB explicitly — no global state, fully testable.
//
// Public API:
//   CreateUser(db, username, password, isAdmin, createdBy) (*User, error)
//   GetUserByID(db, id)                                    (*User, error)
//   GetUserByUsername(db, username)                        (*User, error)
//   ListUsers(db)                                          ([]User, error)
//   DeleteUser(db, id)                                     error
//   UpdatePassword(db, id, newPassword)                    error
//   SetMustChangePw(db, id, val)                           error
//   CountUsers(db)                                         (int, error)
//   CountAdmins(db)                                        (int, error)
package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// User represents an iocscan user account.
type User struct {
	ID           string
	Username     string
	PasswordHash string
	IsAdmin      bool
	MustChangePw bool
	CreatedAt    time.Time
	CreatedBy    string // user ID of creator; empty for bootstrap admin
}

// newID generates a random 16-byte hex ID (32 hex chars).
// Using crypto/rand — no sequential IDs that reveal creation order.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CreateUser inserts a new user. Password is hashed before storage.
// New users always have mustChangePw = true so they set their own password
// on first login.
func CreateUser(db *sql.DB, username, password string, isAdmin bool, createdBy string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if len(password) < 1 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	id, err := newID()
	if err != nil {
		return nil, err
	}

	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	u := &User{
		ID:           id,
		Username:     username,
		PasswordHash: hash,
		IsAdmin:      isAdmin,
		MustChangePw: true,
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    createdBy,
	}

	isAdminInt := 0
	if isAdmin {
		isAdminInt = 1
	}

	_, err = db.Exec(
		`INSERT INTO users (id, username, password_hash, is_admin, must_change_pw, created_at, created_by)
		 VALUES (?, ?, ?, ?, 1, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, isAdminInt, u.CreatedAt.Format(time.RFC3339), u.CreatedBy,
	)
	if err != nil {
		// Surface duplicate username as a readable error.
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, fmt.Errorf("username %q already exists", username)
		}
		return nil, fmt.Errorf("inserting user: %w", err)
	}
	return u, nil
}

// GetUserByID retrieves a user by their ID.
// Returns (nil, nil) if the user does not exist.
func GetUserByID(db *sql.DB, id string) (*User, error) {
	return scanUser(db.QueryRow(
		`SELECT id, username, password_hash, is_admin, must_change_pw, created_at, created_by
		 FROM users WHERE id = ?`, id,
	))
}

// GetUserByUsername retrieves a user by their username (case-insensitive).
// Returns (nil, nil) if the user does not exist.
func GetUserByUsername(db *sql.DB, username string) (*User, error) {
	return scanUser(db.QueryRow(
		`SELECT id, username, password_hash, is_admin, must_change_pw, created_at, created_by
		 FROM users WHERE LOWER(username) = LOWER(?)`, username,
	))
}

// ListUsers returns all users ordered by creation time ascending.
func ListUsers(db *sql.DB) ([]User, error) {
	rows, err := db.Query(
		`SELECT id, username, password_hash, is_admin, must_change_pw, created_at, created_by
		 FROM users ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		u, err := scanUserRow(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

// DeleteUser removes a user by ID.
// Callers must check:
//   - Cannot delete self
//   - Cannot delete last admin (use CountAdmins before calling)
func DeleteUser(db *sql.DB, id string) error {
	res, err := db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// UpdatePassword hashes newPassword and stores it.
// Also clears must_change_pw so the user is not forced to change again.
func UpdatePassword(db *sql.DB, id, newPassword string) error {
	if len(newPassword) < 1 {
		return fmt.Errorf("password cannot be empty")
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`UPDATE users SET password_hash = ?, must_change_pw = 0 WHERE id = ?`,
		hash, id,
	)
	if err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	return nil
}

// SetMustChangePw updates the must_change_pw flag for a user.
func SetMustChangePw(db *sql.DB, id string, val bool) error {
	v := 0
	if val {
		v = 1
	}
	_, err := db.Exec(`UPDATE users SET must_change_pw = ? WHERE id = ?`, v, id)
	if err != nil {
		return fmt.Errorf("setting must_change_pw: %w", err)
	}
	return nil
}

// CountUsers returns the total number of users in the database.
func CountUsers(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("counting users: %w", err)
	}
	return n, nil
}

// CountAdmins returns the number of admin users.
// Used before DeleteUser to prevent deleting the last admin.
func CountAdmins(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_admin = 1`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("counting admins: %w", err)
	}
	return n, nil
}

// ── Row scanning helpers ──────────────────────────────────────────────────────

// scanUser wraps a single *sql.Row.
func scanUser(row *sql.Row) (*User, error) {
	u := &User{}
	var isAdminInt, mustChangePwInt int
	var createdAtStr, createdBy string

	err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash,
		&isAdminInt, &mustChangePwInt,
		&createdAtStr, &createdBy,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanning user: %w", err)
	}

	u.IsAdmin = isAdminInt == 1
	u.MustChangePw = mustChangePwInt == 1
	u.CreatedBy = createdBy

	t, err := time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		// Fallback for rows stored before RFC3339 format was enforced.
		t, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
	}
	u.CreatedAt = t
	return u, nil
}

// scanUserRow wraps *sql.Rows for use in ListUsers.
func scanUserRow(rows *sql.Rows) (*User, error) {
	u := &User{}
	var isAdminInt, mustChangePwInt int
	var createdAtStr, createdBy string

	err := rows.Scan(
		&u.ID, &u.Username, &u.PasswordHash,
		&isAdminInt, &mustChangePwInt,
		&createdAtStr, &createdBy,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning user row: %w", err)
	}

	u.IsAdmin = isAdminInt == 1
	u.MustChangePw = mustChangePwInt == 1
	u.CreatedBy = createdBy

	t, err := time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		t, _ = time.Parse("2006-01-02 15:04:05", createdAtStr)
	}
	u.CreatedAt = t
	return u, nil
}
