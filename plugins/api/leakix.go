// Copyright © by Jeff Foley 2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/owasp-amass/engine/net/dns"
	"github.com/owasp-amass/engine/net/http"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type leakix struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewLeakIX() et.Plugin {
	return &leakix{
		name:   "LeakIX",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
	}
}

func (ix *leakix) Name() string {
	return ix.name
}

func (ix *leakix) Start(r et.Registry) error {
	ix.log = r.Log().WithGroup("plugin").With("name", ix.name)

	name := ix.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     ix,
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   ix.check,
	}); err != nil {
		return err
	}

	ix.log.Info("Plugin started")
	return nil
}

func (ix *leakix) Stop() {
	ix.log.Info("Plugin stopped")
}

func (ix *leakix) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(ix.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	var body string
	for _, cr := range ds.Creds {
		if cr == nil || cr.Apikey == "" {
			continue
		}

		ix.rlimit.Take()
		r, err := ix.query(domlt, cr.Apikey)
		if err == nil {
			body = r
			break
		}

		e.Session.Log().Error(fmt.Sprintf("Failed to use the API endpoint: %v", err),
			slog.Group("plugin", "name", ix.name, "handler", ix.name+"-Handler"))
	}

	if body != "" {
		ix.process(e, body)
	}
	return nil
}

func (ix *leakix) query(domain, key string) (string, error) {
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		URL:    "https://leakix.net/api/subdomains/" + domain,
		Header: map[string]string{"Accept": "application/json", "api-key": key},
	})
	if err != nil {
		return "", err
	}
	return resp.Body, nil
}

func (ix *leakix) process(e *et.Event, body string) {
	var result struct {
		Subdomains []struct {
			FQDN string `json:"subdomain"`
		} `json:"subdomains"`
	}

	body = "{\"subdomains\":" + body + "}"
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return
	}

	for _, s := range result.Subdomains {
		fqdn := dns.RemoveAsteriskLabel(s.FQDN)
		// if the subdomain is not in scope, skip it
		name := strings.ToLower(strings.TrimSpace(fqdn))
		if name != "" && e.Session.Config().IsDomainInScope(name) {
			support.SubmitFQDNGuess(e, name)
		}
	}
}
