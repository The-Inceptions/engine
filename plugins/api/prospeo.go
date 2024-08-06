// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type Prospeo struct {
	name     string
	counturl string
	queryurl string
	log      *slog.Logger
	rlimit   ratelimit.Limiter
}

func NewProspeo() et.Plugin {
	return &Prospeo{
		name:     "Prospeo",
		counturl: "https://api.prospeo.io/email-count",
		queryurl: "https://api.prospeo.io/domain-search",
		rlimit:   ratelimit.New(15, ratelimit.WithoutSlack),
	}
}

func (p *Prospeo) Name() string {
	return p.name
}

func (p *Prospeo) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)

	name := p.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     p,
		Name:       name,
		Transforms: []string{"emailaddress"},
		EventType:  oam.FQDN,
		Callback:   p.check,
	}); err != nil {
		return err
	}

	p.log.Info("Plugin started")

	return nil
}

func (p *Prospeo) Stop() {
	p.log.Info("Plugin stopped")
}

func (p *Prospeo) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("invalid asset type")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))

	matches, err := e.Session.Config().CheckTransformations(
		"fqdn", "emailaddress", p.name)
	if err != nil || matches.Len() == 0 {
		return err
	}

	p.rlimit.Take()

	api, rcreds, err := p.account_type(e)
	if err != nil || api == "" {
		return err
	}

	count, err := p.count(domlt, api)
	if err != nil {
		return err
	}

	emails, err := p.query(domlt, count, api, rcreds)
	if err != nil {
		return err
	}

	support.ProcessEmail(e, emails)
	return nil

}

func (p *Prospeo) count(domain string, api string) (int, error) {
	// Create the request body
	body := []byte(`{"domain": "` + domain + `"}`)

	// Create a new HTTP request
	req, err := http.NewRequest("POST", p.counturl, bytes.NewBuffer(body))
	if err != nil {
		return 0, err
	}

	// Set the request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KEY", api)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyString := responseToString(resp)

	type responseJSON struct {
		Response struct {
			Count int `json:"count"`
		} `json:"response"`
	}

	var response responseJSON

	// decode the json then return the total only
	if err := json.NewDecoder(strings.NewReader(bodyString)).Decode(&response); err != nil {
		return 0, err
	}
	return response.Response.Count, nil

}

func (p *Prospeo) query(domain string, count int, api string, rcredits int) ([]string, error) {

	limit := 0

	if rcredits*50 > count {
		limit = count
	} else {
		limit = rcredits * 50
	}
	body := []byte(`{"company": "` + domain + `", "limit": ` + strconv.Itoa(limit) + `}`)

	// Create a new HTTP request
	req, err := http.NewRequest("POST", p.queryurl, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	// Set the request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KEY", api)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyString := responseToString(resp)

	type responseJSON struct {
		Response struct {
			Emails []struct {
				Email string `json:"email"`
			} `json:"email_list"`
		} `json:"response"`
	}

	var response responseJSON

	result := []string{}

	// decode the json then append the emails to the result
	if err := json.NewDecoder(strings.NewReader(bodyString)).Decode(&response); err != nil {
		return nil, err
	}
	for _, data := range response.Response.Emails {
		result = append(result, data.Email)
	}

	return result, nil
}

func (p *Prospeo) account_type(e *et.Event) (string, int, error) {

	api, err := support.GetAPI(p.name, e)
	if err != nil {
		return "", 0, err
	}

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "https://api.prospeo.io/account-information", nil)
	if err != nil {
		return "", 0, err
	}

	// Set the request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-KEY", api)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyString := responseToString(resp)

	// process the JSON response by taking the output and marshalling it into the struct
	type responseJSON struct {
		Response struct {
			Remaining_credits int `json:"remaining_credits"`
		} `json:"response"`
	}

	var response responseJSON

	// decode the json then return the total only
	if err := json.NewDecoder(strings.NewReader(bodyString)).Decode(&response); err != nil {
		return "", 0, err
	}
	// return the remaining credits
	rcreds := response.Response.Remaining_credits
	return api, rcreds, nil
}

func responseToString(resp *http.Response) string {
	var buffer bytes.Buffer
	_, err := buffer.ReadFrom(resp.Body)
	if err != nil {
		return ""
	}
	return buffer.String()
}
