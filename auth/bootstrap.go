// auth/bootstrap.go — First-run admin account creation.
//
// BootstrapAdmin checks whether any users exist in the database.
// If none exist (fresh install), it creates the default admin account:
//
//	username: admin
//	password: admin
//	is_admin: true
//	must_change_pw: true
//
// The admin is forced to change their password on first login.
// The scanner is unreachable until the password is changed — enforced
// at middleware level, not just as a frontend hint.
//
// Called from server.Start() before the HTTP listener binds.
package auth

import (
	"database/sql"
	"fmt"
)

// BootstrapAdmin creates the default admin account if no users exist.
// Safe to call on every startup — no-op if users already exist.
func BootstrapAdmin(db *sql.DB) error {
	n, err := CountUsers(db)
	if err != nil {
		return fmt.Errorf("bootstrap: counting users: %w", err)
	}
	if n > 0 {
		// Users already exist — nothing to do.
		return nil
	}

	admin, err := CreateUser(db, "admin", "admin", true, "")
	if err != nil {
		return fmt.Errorf("bootstrap: creating admin user: %w", err)
	}

	// CreateUser sets must_change_pw = true by default, but be explicit here
	// so it's clear this is intentional behaviour for the bootstrap account.
	if err := SetMustChangePw(db, admin.ID, true); err != nil {
		return fmt.Errorf("bootstrap: setting must_change_pw: %w", err)
	}

	fmt.Println("⚠️  First run detected — default admin account created.")
	fmt.Println("   Username: admin")
	fmt.Println("   Password: admin")
	fmt.Println("   ⚠️  Change this password immediately after first login!")

	return nil
}
