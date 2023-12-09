// Copyright © by Jeff Foley 2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"log"
	"os"

	"github.com/owasp-amass/engine/api/graphql/server"
	"github.com/owasp-amass/engine/dispatcher"
	"github.com/owasp-amass/engine/registry"
	"github.com/owasp-amass/engine/sessions"
	et "github.com/owasp-amass/engine/types"
)

type Engine struct {
	Log        *log.Logger
	Dispatcher et.Dispatcher
	Registry   et.Registry
	Manager    et.SessionManager
	Server     *server.Server
}

func NewEngine(l *log.Logger) (*Engine, error) {
	if l == nil {
		l = log.New(os.Stdout, "", log.Lmicroseconds)
	}

	reg := registry.NewRegistry(l)
	if reg == nil {
		return nil, errors.New("failed to create the handler registry")
	}

	mgr := sessions.NewManager(l)
	if mgr == nil {
		return nil, errors.New("failed to create the session manager")
	}

	dis := dispatcher.NewDispatcher(l, reg, mgr)
	if dis == nil {
		mgr.Shutdown()
		return nil, errors.New("failed to create the event scheduler")
	}

	srv := server.NewServer(l, dis, mgr)
	if srv == nil {
		dis.Shutdown()
		mgr.Shutdown()
		return nil, errors.New("failed to create the API server")
	}
	go func() { _ = srv.Start() }()

	return &Engine{
		Log:        l,
		Dispatcher: dis,
		Registry:   reg,
		Manager:    mgr,
		Server:     srv,
	}, nil
}

func (e *Engine) Shutdown() {
	_ = e.Server.Shutdown()
	e.Dispatcher.Shutdown()
	e.Manager.Shutdown()
}
