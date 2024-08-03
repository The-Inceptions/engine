// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/owasp-amass/engine/net/http"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type hunterIO struct {
	name             string
	counturl         string
	queryurl         string
	emailVerifierurl string
	accounttype      string
	log              *slog.Logger
	rlimit           ratelimit.Limiter
}

func NewHunterIO() et.Plugin {
	return &hunterIO{
		name:             "HunterIO",
		counturl:         "https://api.hunter.io/v2/email-count?domain=",
		queryurl:         "https://api.hunter.io/v2/domain-search?domain=",
		emailVerifierurl: "https://api.hunter.io/v2/email-verifier?email=",
		rlimit:           ratelimit.New(15, ratelimit.WithoutSlack),
	}
}

func (h *hunterIO) Name() string {
	return h.name
}

func (h *hunterIO) Start(r et.Registry) error {
	h.log = r.Log().WithGroup("plugin").With("name", h.name)

	name := h.name + "-Email-Generation-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     h,
		Name:       name,
		Transforms: []string{"email"},
		EventType:  oam.FQDN,
		Callback:   h.check,
	}); err != nil {
		return err
	}

	name = h.name + "-Email-Verification-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     h,
		Name:       name,
		Transforms: []string{},
		EventType:  oam.Email,
		Callback:   h.verify,
	}); err != nil {
		return err
	}

	h.log.Info("Plugin started")
	return nil
}

func (h *hunterIO) Stop() {
	h.log.Info("Plugin stopped")
}

func (h *hunterIO) verify(e *et.Event) error {
	email, ok := e.Asset.Asset.(*contact.EmailAddress)
	if !ok {
		return errors.New("invalid asset type")
	}

	h.rlimit.Take()

	api, err := support.GetAPI(h.name, e)
	if err != nil {
		return err
	}

	type responseJSON struct {
		Data struct {
			Status string `json:"status"`
			Result string `json:"result"`
		} `json:"data"`
	}

	var result responseJSON

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: h.emailVerifierurl + email.Address + "&api_key=" + api})
	if err != nil {
		return err
	}

	if err := json.NewDecoder(strings.NewReader(resp.Body)).Decode(&result); err != nil {
		return err
	}

	// add it so that it skips risky
	if result.Data.Status != "unknown" && result.Data.Status != "invalid" &&
		result.Data.Status != "disposable" {
		support.ProcessEmail(e, []string{email.Address}, true)
	}

	return nil
}

func (h *hunterIO) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("invalid asset type")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))

	matches, err := e.Session.Config().CheckTransformations(
		"fqdn", "email", h.name)
	if err != nil || matches.Len() == 0 {
		return err
	}

	h.rlimit.Take()
	count, err := h.count(domlt)
	if err != nil {
		return err
	} else {
		api, err := h.account_type(e)
		if err != nil {
			return err
		}
		results, err := h.query(domlt, count, api)
		if err != nil {
			return err
		}
		support.ProcessEmail(e, results, !support.IsVerify(e, h.name))
	}
	return nil
}

func (h *hunterIO) account_type(e *et.Event) (string, error) {

	api, err := support.GetAPI(h.name, e)
	if err != nil {
		return "", err
	}

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: "https://api.hunter.io/v2/account?api_key=" + api})
	if err != nil {
		return "", err
	}

	// make a struct to hold the response since it returns as json
	type responseJSON struct {
		Data struct {
			Plan string `json:"plan_name"`
		} `json:"data"`
	}

	var response responseJSON

	// decode the json then return the total only
	if err := json.NewDecoder(strings.NewReader(resp.Body)).Decode(&response); err != nil {
		return "", err
	}
	h.accounttype = response.Data.Plan
	return api, nil
}

func (h *hunterIO) count(domain string) (int, error) {
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: h.counturl + domain})
	if err != nil {
		return 0, err
	}

	// make a struct to hold the response since it returns as json
	type responseJSON struct {
		Data struct {
			Total int `json:"total"`
		} `json:"data"`
	}

	var response responseJSON

	// decode the json then return the total only
	if err := json.NewDecoder(strings.NewReader(resp.Body)).Decode(&response); err != nil {
		return 0, err
	}
	return response.Data.Total, nil

}

func (h *hunterIO) query(domain string, count int, api string) ([]string, error) {
	var result []string

	// make a struct to hold the response since it returns as json
	type responseJSON struct {
		Data struct {
			Email []struct {
				Value string `json:"value"`
			} `json:"emails"`
		} `json:"data"`
	}

	var response responseJSON

	// if the count is less than or equal to 10, we can get all the emails in one request
	// TODO: add another condition for free API keys, since they could only get the first ten anyways.
	if count <= 10 || h.accounttype == "Free" {
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: h.queryurl + domain + "&api_key=" + api})
		if err != nil {
			return nil, err
		}
		if err := json.NewDecoder(strings.NewReader(resp.Body)).Decode(&response); err != nil {
			return nil, err
		}
		for _, data := range response.Data.Email {
			result = append(result, data.Value)
		}

	} else {
		for offset := 0; offset < count; offset += 100 {
			resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: h.queryurl + domain + "&api_key=" + api + "&limit=100&offset=" + strconv.Itoa(offset)})
			if err != nil && resp.StatusCode != 400 {
				return nil, err
			} else if resp.StatusCode == 400 { // since the API returns 400 when the limit is exceeded or if any error occurs, we break the loop
				break
			}
			if err := json.NewDecoder(strings.NewReader(resp.Body)).Decode(&response); err != nil {
				return nil, err
			}
			for _, data := range response.Data.Email {
				result = append(result, data.Value)
			}

		}
	}

	return result, nil
}
