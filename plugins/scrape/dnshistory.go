// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scrape

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/owasp-amass/engine/net/http"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type dnsHistory struct {
	name   string
	fmtstr string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewDNSHistory() et.Plugin {
	return &dnsHistory{
		name:   "DNSHistory",
		fmtstr: "https://dnshistory.org/subdomains/%d/%s",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
	}
}

func (d *dnsHistory) Name() string {
	return d.name
}

func (d *dnsHistory) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	name := "DNSHistory-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     d,
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   d.check,
	}); err != nil {
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *dnsHistory) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *dnsHistory) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	for i := 1; i < 20; i++ {
		d.rlimit.Take()
		if body, err := d.query(domlt, i); err == nil {
			d.process(e, body)
		}
	}
	return nil
}

func (d *dnsHistory) query(name string, itemnum int) (string, error) {
	req := &http.Request{URL: fmt.Sprintf(d.fmtstr, itemnum, name)}

	resp, err := http.RequestWebPage(context.TODO(), req)
	if err != nil {
		return "", err
	}

	return resp.Body, nil
}

func (d *dnsHistory) process(e *et.Event, body string) {
	for _, name := range support.ScrapeSubdomainNames(body) {
		n := strings.ToLower(strings.TrimSpace(name))
		// if the subdomain is not in scope, skip it
		if n != "" && e.Session.Config().IsDomainInScope(n) {
			support.SubmitFQDNGuess(e, n)
		}
	}
}
