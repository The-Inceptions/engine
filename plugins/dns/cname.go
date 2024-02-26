// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/graph"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/resolve"
)

type dnsCNAME struct {
	Name   string
	dblock sync.Mutex
	log    *slog.Logger
}

func NewCNAME() et.Plugin {
	return &dnsCNAME{Name: "DNS-CNAME"}
}

func (d *dnsCNAME) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.Name)

	name := "DNS-CNAME-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Name:         name,
		Priority:     1,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.handler,
	}); err != nil {
		d.log.Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *dnsCNAME) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *dnsCNAME) handler(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "fqdn", "dns")
	if err != nil {
		return err
	}
	if !matches.IsMatch("fqdn") {
		return nil
	}

	if rr, err := support.PerformQuery(fqdn.Name, dns.TypeCNAME); err == nil && len(rr) > 0 {
		d.processRecords(e, rr)
	}
	return nil
}

func (d *dnsCNAME) processRecords(e *et.Event, rr []*resolve.ExtractedAnswer) {
	g := graph.Graph{DB: e.Session.DB()}

	for _, record := range rr {
		d.dblock.Lock()
		a, err := g.UpsertCNAME(context.TODO(), record.Name, record.Data)
		d.dblock.Unlock()
		if err == nil && a != nil {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    record.Data,
				Asset:   a,
				Session: e.Session,
			})

			now := time.Now()
			if cname, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: record.Name}); hit && cname != nil {
				e.Session.Cache().SetRelation(&dbt.Relation{
					Type:      "cname_record",
					CreatedAt: now,
					LastSeen:  now,
					FromAsset: cname,
					ToAsset:   a,
				})

				e.Session.Log().Info("relationship discovered", "from",
					record.Name, "relation", "cname_record", "to", record.Data,
					slog.Group("plugin", "name", d.Name, "handler", "DNS-CNAME-Handler"))
			}
		}
	}
}
