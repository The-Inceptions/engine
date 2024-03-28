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

type chaos struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewChaos() et.Plugin {
	return &chaos{
		name:   "Chaos",
		rlimit: ratelimit.New(10, ratelimit.WithoutSlack),
	}
}

func (c *chaos) Name() string {
	return c.name
}

func (c *chaos) Start(r et.Registry) error {
	c.log = r.Log().WithGroup("plugin").With("name", c.name)

	name := c.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     c,
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   c.check,
	}); err != nil {
		return err
	}

	c.log.Info("Plugin started")
	return nil
}

func (c *chaos) Stop() {
	c.log.Info("Plugin stopped")
}

func (c *chaos) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(c.name)
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

		c.rlimit.Take()
		r, err := c.query(domlt, cr.Apikey)
		if err == nil {
			body = r
			break
		}

		e.Session.Log().Error(fmt.Sprintf("Failed to use the API endpoint: %v", err),
			slog.Group("plugin", "name", c.name, "handler", c.name+"-Handler"))
	}

	if body != "" {
		c.process(e, domlt, body)
	}
	return nil
}

func (c *chaos) query(domain, key string) (string, error) {
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		URL:    "https://dns.projectdiscovery.io/dns/" + domain + "/subdomains",
		Header: map[string]string{"Authorization": key},
	})
	if err != nil {
		return "", err
	}
	return resp.Body, nil
}

func (c *chaos) process(e *et.Event, domain, body string) {
	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return
	}

	for _, sub := range result.Subdomains {
		fqdn := dns.RemoveAsteriskLabel(sub + "." + domain)
		// if the subdomain is not in scope, skip it
		name := strings.ToLower(strings.TrimSpace(fqdn))
		if name != "" && e.Session.Config().IsDomainInScope(name) {
			support.SubmitFQDNGuess(e, name)
		}
	}
}
