// Copyright © by Jeff Foley 2023-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"unicode"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
)

type alts struct {
	Name  string
	log   *slog.Logger
	chars string
}

func NewAlterations() et.Plugin {
	return &alts{
		Name:  "FQDN-Alterations",
		chars: "abcdefghijklmnopqrstuvwxyz0123456789-",
	}
}

func (d *alts) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.Name)

	name := "DNS-Alterations-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Name:         name,
		Priority:     7,
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

func (d *alts) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *alts) handler(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	cfg := e.Session.Config()
	if cfg != nil && (!cfg.BruteForcing || !cfg.Alterations) {
		return nil
	}

	matches, err := e.Session.Config().CheckTransformations("fqdn", "fqdn", "dns")
	if err != nil {
		return err
	}
	if !matches.IsMatch("fqdn") {
		return nil
	}

	if !support.NameResolved(e.Session, fqdn) {
		return nil
	}

	guesses := stringset.New()
	if cfg.FlipWords && len(cfg.AltWordlist) > 0 {
		guesses.InsertMany(flipWords(fqdn.Name, cfg.AltWordlist)...)
	}
	if cfg.FlipNumbers {
		guesses.InsertMany(flipNumbers(fqdn.Name)...)
	}
	if cfg.AddNumbers {
		guesses.InsertMany(appendNumbers(fqdn.Name)...)
	}
	if cfg.AddWords && len(cfg.AltWordlist) > 0 {
		guesses.InsertMany(addPrefixWords(fqdn.Name, cfg.AltWordlist)...)
		guesses.InsertMany(addSuffixWords(fqdn.Name, cfg.AltWordlist)...)
	}
	if distance := cfg.EditDistance; distance > 0 {
		guesses.InsertMany(fuzzyLabelSearches(fqdn.Name, distance, d.chars)...)
	}
	for _, guess := range guesses.Slice() {
		support.SubmitFQDNGuess(e, guess)
	}
	return nil
}

// flipWords flips prefixes and suffixes found within the provided name.
func flipWords(name string, words []string) []string {
	names := strings.SplitN(name, ".", 2)
	subdomain := names[0]
	domain := names[1]

	parts := strings.Split(subdomain, "-")
	if len(parts) < 2 {
		return []string{}
	}

	results := stringset.New()
	for _, k := range words {
		results.Insert(k + "-" + strings.Join(parts[1:], "-") + "." + domain)
	}

	for _, k := range words {
		results.Insert(strings.Join(parts[:len(parts)-1], "-") + "-" + k + "." + domain)
	}
	return results.Slice()
}

// flipNumbers flips numbers in a subdomain name.
func flipNumbers(name string) []string {
	n := name
	parts := strings.SplitN(n, ".", 2)
	// Find the first character that is a number
	first := strings.IndexFunc(parts[0], unicode.IsNumber)
	if first < 0 {
		return []string{}
	}

	results := stringset.New()
	// Flip the first number and attempt a second number
	for i := 0; i < 10; i++ {
		sf := n[:first] + strconv.Itoa(i) + n[first+1:]

		results.InsertMany(secondNumberFlip(sf, first+1)...)
	}
	// Take the first number out
	results.InsertMany(secondNumberFlip(n[:first]+n[first+1:], -1)...)
	return results.Slice()
}

func secondNumberFlip(name string, minIndex int) []string {
	parts := strings.SplitN(name, ".", 2)
	// Find the second character that is a number
	last := strings.LastIndexFunc(parts[0], unicode.IsNumber)
	if last < 0 || last < minIndex {
		return []string{name}
	}

	var results []string
	// Flip those numbers and send out the mutations
	for i := 0; i < 10; i++ {
		results = append(results, name[:last]+strconv.Itoa(i)+name[last+1:])
	}
	// Take the second number out
	results = append(results, name[:last]+name[last+1:])
	return results
}

// appendNumbers appends a number to a subdomain name.
func appendNumbers(name string) []string {
	parts := strings.SplitN(name, ".", 2)

	parts[0] = strings.Trim(parts[0], "-")
	if parts[0] == "" {
		return []string{}
	}

	results := stringset.New()
	for i := 0; i < 10; i++ {
		results.InsertMany(addSuffix(parts, strconv.Itoa(i))...)
	}
	return results.Slice()
}

// addSuffixWords appends a suffix to a subdomain name.
func addSuffixWords(name string, words []string) []string {
	parts := strings.SplitN(name, ".", 2)

	parts[0] = strings.Trim(parts[0], "-")
	if parts[0] == "" {
		return []string{}
	}

	results := stringset.New()
	for _, word := range words {
		results.InsertMany(addSuffix(parts, word)...)
	}
	return results.Slice()
}

// addPrefixWords appends a subdomain name to a prefix.
func addPrefixWords(name string, words []string) []string {
	name = strings.Trim(name, "-")
	if name == "" {
		return []string{}
	}

	results := stringset.New()
	for _, word := range words {
		results.InsertMany(addPrefix(name, word)...)
	}
	return results.Slice()
}

func addSuffix(parts []string, suffix string) []string {
	return []string{
		parts[0] + suffix + "." + parts[1],
		parts[0] + "-" + suffix + "." + parts[1],
	}
}

func addPrefix(name, prefix string) []string {
	return []string{
		prefix + name,
		prefix + "-" + name,
	}
}

// fuzzyLabelSearches returns new names generated by making slight
// mutations to the provided name.
func fuzzyLabelSearches(name string, distance int, chars string) []string {
	parts := strings.SplitN(name, ".", 2)

	var results []string
	if len(parts) < 2 {
		return results
	}

	results = append(results, parts[0])
	for i := 0; i < distance; i++ {
		var conv []string

		conv = append(conv, additions(results, chars)...)
		conv = append(conv, deletions(results)...)
		conv = append(conv, substitutions(results, chars)...)
		results = append(results, conv...)
	}

	names := stringset.New()
	for _, alt := range results {
		if label := strings.Trim(alt, "-"); label != "" {
			names.Insert(label + "." + parts[1])
		}
	}
	return names.Slice()
}

func additions(set []string, chars string) []string {
	ldh := []rune(chars)
	ldhLen := len(ldh)

	var results []string
	for _, str := range set {
		rstr := []rune(str)
		rlen := len(rstr)

		for i := 0; i <= rlen; i++ {
			for j := 0; j < ldhLen; j++ {
				temp := append(rstr, ldh[0])

				copy(temp[i+1:], temp[i:])
				temp[i] = ldh[j]
				results = append(results, string(temp))
			}
		}
	}
	return results
}

func deletions(set []string) []string {
	var results []string

	for _, str := range set {
		rstr := []rune(str)
		rlen := len(rstr)

		for i := 0; i < rlen; i++ {
			if del := string(append(rstr[:i], rstr[i+1:]...)); del != "" {
				results = append(results, del)
			}
		}
	}
	return results
}

func substitutions(set []string, chars string) []string {
	ldh := []rune(chars)
	ldhLen := len(ldh)

	var results []string
	for _, str := range set {
		rstr := []rune(str)
		rlen := len(rstr)

		for i := 0; i < rlen; i++ {
			temp := rstr

			for j := 0; j < ldhLen; j++ {
				temp[i] = ldh[j]
				results = append(results, string(temp))
			}
		}
	}
	return results
}
