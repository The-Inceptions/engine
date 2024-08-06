// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/owasp-amass/engine/plugins/api"
	et "github.com/owasp-amass/engine/types"
)

var pluginNewFuncs = []func() et.Plugin{
	// api.NewBinaryEdge,
	// api.NewChaos,
	// api.NewDNSRepo,
	// api.NewHackerTarget,
	// api.NewBGPTools,
	// api.NewLeakIX,
	// api.NewPassiveTotal,
	// api.NewSecurityTrails,
	// api.NewURLScan,
	// api.NewVirusTotal,
	// api.NewZetalytics,
	api.NewHunterIO,
	api.NewProspeo,
	api.NewGrepApp,
	// archive.NewWayback,
	// dns.NewDNS,
	// scrape.NewBing,
	// scrape.NewDNSHistory,
	// scrape.NewDuckDuckGo,
	// scrape.NewRapidDNS,
	// scrape.NewSiteDossier,
	// NewIPNetblock,
	// NewKnownFQDN,
	NewVerifiedEmail,
}

func LoadAndStartPlugins(r et.Registry) error {
	var started []et.Plugin

	for _, f := range pluginNewFuncs {
		if p := f(); p != nil {
			if err := p.Start(r); err != nil {
				stopPlugins(started)
				return err
			}
		}
	}
	return nil
}

func stopPlugins(started []et.Plugin) {
	for _, p := range started {
		p.Stop()
	}
}
