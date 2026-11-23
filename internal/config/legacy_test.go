// Copyright (C) 2026 D-Modem Authors
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLegacy: the new path, unless only the old one (modemmenu's) is there
func TestLegacy(t *testing.T) {
	dir := t.TempDir()
	nw, old := filepath.Join(dir, "dmodem-login.conf"), filepath.Join(dir, "modemmenu.conf")
	if got := Legacy(nw, old); got != nw {
		t.Errorf("neither: %s", got)
	}
	os.WriteFile(old, nil, 0o600)
	if got := Legacy(nw, old); got != old {
		t.Errorf("old only: %s", got)
	}
	os.WriteFile(nw, nil, 0o600)
	if got := Legacy(nw, old); got != nw {
		t.Errorf("both: %s", got)
	}
}
