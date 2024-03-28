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

type siteDossier struct {
	name   string
	fmtstr string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewSiteDossier() et.Plugin {
	return &siteDossier{
		name:   "SiteDossier",
		fmtstr: "http://www.sitedossier.com/parentdomain/%s/%d",
		rlimit: ratelimit.New(4, ratelimit.WithoutSlack),
	}
}

func (sd *siteDossier) Name() string {
	return sd.name
}

func (sd *siteDossier) Start(r et.Registry) error {
	sd.log = r.Log().WithGroup("plugin").With("name", sd.name)

	name := sd.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     sd,
		Name:       name,
		Transforms: []string{"fqdn"},
		EventType:  oam.FQDN,
		Callback:   sd.check,
	}); err != nil {
		return err
	}

	sd.log.Info("Plugin started")
	return nil
}

func (sd *siteDossier) Stop() {
	sd.log.Info("Plugin stopped")
}

func (sd *siteDossier) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	for i := 1; i < 20; i++ {
		sd.rlimit.Take()
		if body, err := sd.query(domlt, i); err == nil {
			sd.process(e, body)
		}
	}
	return nil
}

func (sd *siteDossier) query(name string, itemnum int) (string, error) {
	req := &http.Request{URL: fmt.Sprintf(sd.fmtstr, name, itemnum)}

	resp, err := http.RequestWebPage(context.TODO(), req)
	if err != nil {
		return "", err
	}

	return resp.Body, nil
}

func (sd *siteDossier) process(e *et.Event, body string) {
	for _, name := range support.ScrapeSubdomainNames(body) {
		n := strings.ToLower(strings.TrimSpace(name))
		// if the subdomain is not in scope, skip it
		if n != "" && e.Session.Config().IsDomainInScope(n) {
			support.SubmitFQDNGuess(e, n)
		}
	}
}
