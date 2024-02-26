// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	et "github.com/owasp-amass/engine/types"
)

func TestAddSession(t *testing.T) {
	mgr := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer mgr.Shutdown()

	// Create a new session object
	s := &session{
		id:    uuid.New(),
		stats: new(et.SessionStats),
		done:  make(chan struct{}),
	}

	if _, err := mgr.AddSession(s); err != nil {
		t.Error(err)
	}
}
