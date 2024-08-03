// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/owasp-amass/engine/net/http"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type grepApp struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
}

func NewGrepApp() et.Plugin {
	return &grepApp{
		name:   "GrepApp",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
	}
}

func (g *grepApp) Name() string {
	return g.name
}

func (g *grepApp) Start(r et.Registry) error {
	g.log = r.Log().WithGroup("plugin").With("name", g.name)

	name := g.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     g,
		Name:       name,
		Transforms: []string{"email"},
		EventType:  oam.FQDN,
		Callback:   g.query,
	}); err != nil {
		return err
	}

	g.log.Info("Plugin started")
	return nil
}

func (g *grepApp) Stop() {
	g.log.Info("Plugin stopped")
}

func (g *grepApp) query(e *et.Event) error {

	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("invalid asset type")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	newdlt := strings.ReplaceAll(domlt, ".", `\.`)

	escapedQuery := url.QueryEscape("([a-zA-Z0-9._-]+)@" + newdlt)
	re := regexp.MustCompile(`([a-zA-Z0-9._-]+)@` + newdlt)

	g.rlimit.Take()

	uniqueEmails := make(map[string]struct{})
	results := []string{}

	// make a struct to hold the responses
	type responseJSON struct {
		Hits struct {
			Hits []struct {
				Content struct {
					Snippet string `json:"snippet"`
				} `json:"content"`
			} `json:"hits"`
			Total int `json:"total"`
		} `json:"hits"`
	}

	// unmarshal the response into the struct
	var response responseJSON

	response.Hits.Total = -1

	for page := 1; response.Hits.Total == -1 || response.Hits.Total > 10*page; page++ {
		// Form the full URL
		fullURL := fmt.Sprintf("https://grep.app/api/search?page=%s&q=%s&regexp=true", strconv.Itoa(page), escapedQuery)

		resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: fullURL})
		if err != nil {
			return err
		}

		// decode the json
		if err := json.NewDecoder(strings.NewReader(resp.Body)).Decode(&response); err != nil {
			return err
		}

		// loop through the hits and append the snippets to the results
		for _, hit := range response.Hits.Hits {
			emails := re.FindAllString(hit.Content.Snippet, -1)
			// this is to ensure we have unqiue emails since they may appear multiple times in the same snippet
			for _, email := range emails {
				if _, ok := uniqueEmails[email]; !ok {
					results = append(results, email)
					uniqueEmails[email] = struct{}{}
				}
			}
		}

	}

	support.ProcessEmail(e, results, !support.IsVerify(e, g.name))
	return nil
}
