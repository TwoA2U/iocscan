// auth/keys.go — Per-user API key storage and retrieval.
//
// Keys are stored AES-256-GCM encrypted in the api_keys table.
// The encryption key lives at ~/.iocscan.secret (managed by crypto.go).
//
// Public API:
//   SaveKeys(db, userID, encKey, req)    upsert encrypted keys for a user
//   GetKeys(db, userID, encKey)          decrypt and return keys for a user
//   MaskKey(key)                         return last-4 masked display string
package auth

import (
	"database/sql"
	"fmt"
	"time"
)

// APIKeys holds plaintext API keys for use in scan pipelines.
// Never serialised to JSON directly — use MaskedKeys for frontend responses.
type APIKeys struct {
	VTKey        string
	AbuseKey     string
	IPApiKey     string
	AbuseCHKey   string
	GreyNoiseKey string
}

// SaveKeysRequest is the JSON body for PUT /api/keys.
// Empty string means "don't change this key".
type SaveKeysRequest struct {
	VTKey        string `json:"vtKey"`
	AbuseKey     string `json:"abuseKey"`
	IPApiKey     string `json:"ipapiKey"`
	AbuseCHKey   string `json:"abusechKey"`
	GreyNoiseKey string `json:"greynoiseKey"`
}

// MaskedKeys is the safe JSON response for GET /api/keys.
// Shows only last 4 characters — never exposes plaintext keys.
type MaskedKeys struct {
	VTKey        string `json:"vtKey"`
	AbuseKey     string `json:"abuseKey"`
	IPApiKey     string `json:"ipapiKey"`
	AbuseCHKey   string `json:"abusechKey"`
	GreyNoiseKey string `json:"greynoiseKey"`
}

// MaskKey returns a display-safe version of a key.
// Empty → ""   Short (<= 4 chars) → "••••"   Otherwise → "••••••••<last4>"
func MaskKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 4 {
		return "••••"
	}
	return "••••••••" + key[len(key)-4:]
}

// SaveKeys encrypts and upserts all non-empty keys for a user.
// Keys that arrive as empty string are left unchanged in the DB.
func SaveKeys(db *sql.DB, userID string, encKey []byte, req SaveKeysRequest) error {
	// Load existing encrypted blobs so we only overwrite supplied fields.
	existing, err := loadRawKeys(db, userID)
	if err != nil {
		return err
	}

	// Helper: encrypt new value if non-empty, else keep existing blob.
	update := func(newVal string, existing []byte) ([]byte, error) {
		if newVal == "" {
			return existing, nil // unchanged
		}
		return Encrypt(newVal, encKey)
	}

	vtBlob, err := update(req.VTKey, existing.vt)
	if err != nil {
		return fmt.Errorf("encrypting vt_key: %w", err)
	}
	abuseBlob, err := update(req.AbuseKey, existing.abuse)
	if err != nil {
		return fmt.Errorf("encrypting abuse_key: %w", err)
	}
	ipapiBlob, err := update(req.IPApiKey, existing.ipapi)
	if err != nil {
		return fmt.Errorf("encrypting ipapi_key: %w", err)
	}
	abusechBlob, err := update(req.AbuseCHKey, existing.abusech)
	if err != nil {
		return fmt.Errorf("encrypting abusech_key: %w", err)
	}
	greynoiseBlob, err := update(req.GreyNoiseKey, existing.greynoise)
	if err != nil {
		return fmt.Errorf("encrypting greynoise_key: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.Exec(`
		INSERT INTO api_keys (user_id, vt_key, abuse_key, ipapi_key, abusech_key, greynoise_key, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			vt_key        = excluded.vt_key,
			abuse_key     = excluded.abuse_key,
			ipapi_key     = excluded.ipapi_key,
			abusech_key   = excluded.abusech_key,
			greynoise_key = excluded.greynoise_key,
			updated_at    = excluded.updated_at
	`, userID, vtBlob, abuseBlob, ipapiBlob, abusechBlob, greynoiseBlob, now)
	if err != nil {
		return fmt.Errorf("saving keys: %w", err)
	}
	return nil
}

// GetKeys decrypts and returns all API keys for a user.
// Returns an empty APIKeys struct (all empty strings) if no row exists.
func GetKeys(db *sql.DB, userID string, encKey []byte) (*APIKeys, error) {
	raw, err := loadRawKeys(db, userID)
	if err != nil {
		return nil, err
	}

	decrypt := func(blob []byte, label string) (string, error) {
		v, err := Decrypt(blob, encKey)
		if err != nil {
			return "", fmt.Errorf("decrypting %s: %w", label, err)
		}
		return v, nil
	}

	vt, err := decrypt(raw.vt, "vt_key")
	if err != nil {
		return nil, err
	}
	abuse, err := decrypt(raw.abuse, "abuse_key")
	if err != nil {
		return nil, err
	}
	ipapi, err := decrypt(raw.ipapi, "ipapi_key")
	if err != nil {
		return nil, err
	}
	abusech, err := decrypt(raw.abusech, "abusech_key")
	if err != nil {
		return nil, err
	}
	greynoise, err := decrypt(raw.greynoise, "greynoise_key")
	if err != nil {
		return nil, err
	}

	return &APIKeys{
		VTKey:        vt,
		AbuseKey:     abuse,
		IPApiKey:     ipapi,
		AbuseCHKey:   abusech,
		GreyNoiseKey: greynoise,
	}, nil
}

// ToMasked returns a MaskedKeys safe for the frontend.
func (k *APIKeys) ToMasked() MaskedKeys {
	return MaskedKeys{
		VTKey:        MaskKey(k.VTKey),
		AbuseKey:     MaskKey(k.AbuseKey),
		IPApiKey:     MaskKey(k.IPApiKey),
		AbuseCHKey:   MaskKey(k.AbuseCHKey),
		GreyNoiseKey: MaskKey(k.GreyNoiseKey),
	}
}

// ── Internal helpers ──────────────────────────────────────────────────────────

type rawKeyBlobs struct {
	vt, abuse, ipapi, abusech, greynoise []byte
}

// loadRawKeys reads the raw encrypted blobs from the DB.
// Returns empty blobs (nil slices) if no row exists — not an error.
func loadRawKeys(db *sql.DB, userID string) (rawKeyBlobs, error) {
	var r rawKeyBlobs
	err := db.QueryRow(
		`SELECT vt_key, abuse_key, ipapi_key, abusech_key, greynoise_key
		 FROM api_keys WHERE user_id = ?`, userID,
	).Scan(&r.vt, &r.abuse, &r.ipapi, &r.abusech, &r.greynoise)

	if err == sql.ErrNoRows {
		return rawKeyBlobs{}, nil // first save for this user
	}
	if err != nil {
		return rawKeyBlobs{}, fmt.Errorf("loading keys: %w", err)
	}
	return r, nil
}
