// Copyright © by Jeff Foley 2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"time"

	"github.com/caffix/queue"
	"github.com/miekg/dns"
	"github.com/owasp-amass/engine/graph"
	et "github.com/owasp-amass/engine/types"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/resolve"
	"golang.org/x/net/publicsuffix"
)

type guess struct {
	event *et.Event
	name  string
}

type baseline struct {
	address string
	qps     int
}

// baselineResolvers is a list of trusted public DNS resolvers.
var baselineResolvers = []baseline{
	{"8.8.8.8", 20},         // Google Primary
	{"8.8.4.4", 20},         // Google Secondary
	{"95.85.95.85", 10},     // Gcore DNS Primary
	{"2.56.220.2", 10},      // Gcore DNS Secondary
	{"76.76.2.0", 10},       // ControlD Primary
	{"76.76.10.0", 10},      // ControlD Secondary
	{"9.9.9.9", 10},         // Quad9 Primary
	{"149.112.112.112", 10}, // Quad9 Secondary
	{"208.67.222.222", 10},  // Cisco OpenDNS Home Primary
	{"208.67.220.220", 10},  // Cisco OpenDNS Home Secondary
	{"1.1.1.1", 15},         // Cloudflare Primary
	{"1.0.0.1", 15},         // Cloudflare Secondary
	{"185.228.168.9", 5},    // CleanBrowsing Primary
	{"185.228.169.9", 5},    // CleanBrowsing Secondary
	{"76.76.19.19", 5},      // Alternate DNS Primary
	{"76.223.122.150", 5},   // Alternate DNS Secondary
	{"94.140.14.14", 5},     // AdGuard DNS Primary
	{"94.140.15.15", 5},     // AdGuard DNS Secondary
	{"176.103.130.130", 5},  // AdGuard
	{"176.103.130.131", 5},  // AdGuard
	{"8.26.56.26", 5},       // Comodo Secure DNS Primary
	{"8.20.247.20", 5},      // Comodo Secure DNS Secondary
	{"205.171.3.65", 5},     // CenturyLink Level3 Primary
	{"205.171.2.65", 5},     // CenturyLink Level3 Secondary
	{"64.6.64.6", 5},        // Verisign DNS Primary
	{"64.6.65.6", 5},        // Verisign DNS Secondary
	{"209.244.0.3", 5},      // CenturyLink Level3
	{"209.244.0.4", 5},      // CenturyLink Level3
	{"149.112.121.10", 5},   // CIRA Canadian Shield Primary
	{"149.112.122.10", 5},   // CIRA Canadian Shield Secondary
	{"138.197.140.189", 5},  // OpenNIC Primary
	{"162.243.19.47", 5},    // OpenNIC Secondary
	{"216.87.84.211", 5},    // OpenNIC
	{"23.90.4.6", 5},        // OpenNIC
	{"216.146.35.35", 5},    // Oracle Dyn Primary
	{"216.146.36.36", 5},    // Oracle Dyn Secondary
	{"91.239.100.100", 5},   // UncensoredDNS Primary
	{"89.233.43.71", 5},     // UncensoredDNS Secondary
	{"77.88.8.8", 5},        // Yandex.DNS Primary
	{"77.88.8.1", 5},        // Yandex.DNS Secondary
	{"74.82.42.42", 5},      // Hurricane Electric Primary
	{"94.130.180.225", 5},   // DNS for Family Primary
	{"78.47.64.161", 5},     // DNS for Family Secondary
	{"80.80.80.80", 5},      // Freenom World Primary
	{"80.80.81.81", 5},      // Freenom World Secondary
	{"84.200.69.80", 5},     // DNS.WATCH Primary
	{"84.200.70.40", 5},     // DNS.WATCH Secondary
	{"156.154.70.5", 5},     // Neustar Primary
	{"156.157.71.5", 5},     // Neustar Secondary
	{"81.218.119.11", 5},    // GreenTeamDNS Primary
	{"209.88.198.133", 5},   // GreenTeamDNS Secondary
	{"37.235.1.177", 5},     // FreeDNS
	{"38.132.106.139", 5},   // CyberGhost
}

var trusted *resolve.Resolvers
var guesses queue.Queue

func NumResolvers() int {
	return trusted.Len()
}

func PerformQuery(name string, qtype uint16) ([]*resolve.ExtractedAnswer, error) {
	msg := resolve.QueryMsg(name, qtype)
	if qtype == dns.TypePTR {
		msg = resolve.ReverseMsg(name)
	}

	resp, err := dnsQuery(msg, trusted, 50)
	if err == nil && resp != nil && !wildcardDetected(resp, trusted) {
		if ans := resolve.ExtractAnswers(resp); len(ans) > 0 {
			if rr := resolve.AnswersByType(ans, qtype); len(rr) > 0 {
				return normalize(rr), nil
			}
		}
	}
	return nil, err
}

func SubmitFQDNGuess(e *et.Event, name string) {
	guesses.Append(&guess{
		event: e,
		name:  name,
	})
}

func processGuesses() {
	num := trusted.Len()
	ch := make(chan struct{}, num)
	for i := 0; i < num; i++ {
		ch <- struct{}{}
	}

	for {
		select {
		case <-done:
			return
		case <-guesses.Signal():
			guesses.Process(func(data interface{}) {
				<-ch
				if g, ok := data.(*guess); ok && g != nil {
					go guessAttempt(g.event, g.name, ch)
				}
			})
		}
	}
}

func guessAttempt(e *et.Event, name string, ch chan struct{}) {
	defer func() { ch <- struct{}{} }()

	if _, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: name}); hit {
		return
	}

	for _, qtype := range []uint16{dns.TypeCNAME, dns.TypeA, dns.TypeAAAA} {
		if e.Session.Done() {
			return
		}
		if ans, err := PerformQuery(name, qtype); err == nil && ans != nil {
			guessCallback(e, name)
		}
	}
}

func guessCallback(e *et.Event, name string) {
	g := graph.Graph{DB: e.Session.DB()}

	AppendToDBQueue(func() {
		fqdn, err := g.UpsertFQDN(context.TODO(), name)
		if err != nil {
			e.Session.Log().Error(err.Error())
			return
		}
		if fqdn != nil {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    name,
				Asset:   fqdn,
				Session: e.Session,
			})
		}
	})
}

func wildcardDetected(resp *dns.Msg, r *resolve.Resolvers) bool {
	name := strings.ToLower(resolve.RemoveLastDot(resp.Question[0].Name))

	if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil && dom != "" {
		return r.WildcardDetected(context.TODO(), resp, dom)
	}
	return false
}

func normalize(records []*resolve.ExtractedAnswer) []*resolve.ExtractedAnswer {
	var results []*resolve.ExtractedAnswer

	for _, rr := range records {
		results = append(results, &resolve.ExtractedAnswer{
			Name: strings.ToLower(rr.Name),
			Type: rr.Type,
			Data: strings.ToLower(rr.Data),
		})
	}

	return results
}

func dnsQuery(msg *dns.Msg, r *resolve.Resolvers, attempts int) (*dns.Msg, error) {
	for num := 0; num < attempts; num++ {
		resp, err := r.QueryBlocking(context.TODO(), msg)
		if err != nil {
			continue
		}
		if resp.Rcode == dns.RcodeNameError {
			return nil, errors.New("name does not exist")
		}
		if resp.Rcode == dns.RcodeSuccess {
			if len(resp.Answer) == 0 {
				return nil, errors.New("no record of this type")
			}
			return resp, nil
		}
	}
	return nil, nil
}

func trustedResolvers() (*resolve.Resolvers, int) {
	blr := baselineResolvers
	rand.Shuffle(len(blr), func(i, j int) {
		blr[i], blr[j] = blr[j], blr[i]
	})

	if pool := resolve.NewResolvers(); pool != nil {
		for _, r := range blr {
			_ = pool.AddResolvers(r.qps, r.address)
		}
		pool.SetTimeout(3 * time.Second)
		pool.SetDetectionResolver(50, "8.8.8.8")
		return pool, pool.Len()
	}
	return nil, 0
}
