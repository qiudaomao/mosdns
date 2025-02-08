/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package domain_set

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
)

const PluginType = "domain_set"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	m, err := NewDomainSet(bp, args.(*Args))
	if err != nil {
		return nil, err
	}
	return m, nil
}

type Args struct {
	Exps        []string     `yaml:"exps"`
	Sets        []string     `yaml:"sets"`
	Files       []string     `yaml:"files"`
	RemoteFiles []RemoteFile `yaml:"remote_files"`
}

type RemoteFile struct {
	URL      string `yaml:"url"`
	Path     string `yaml:"path"`
	Interval int    `yaml:"interval"` // in seconds
}

var _ data_provider.DomainMatcherProvider = (*DomainSet)(nil)

type DomainSet struct {
	mg []domain.Matcher[struct{}]
}

func (d *DomainSet) GetDomainMatcher() domain.Matcher[struct{}] {
	return MatcherGroup(d.mg)
}

// NewDomainSet inits a DomainSet from given args.
func NewDomainSet(bp *coremain.BP, args *Args) (*DomainSet, error) {
	ds := &DomainSet{}

	m := domain.NewDomainMixMatcher()
	if err := LoadExpsAndFiles(args.Exps, args.Files, m); err != nil {
		return nil, err
	}

	// Handle remote files
	for _, rf := range args.RemoteFiles {
		if err := LoadRemoteFile(rf, m); err != nil {
			return nil, fmt.Errorf("failed to load remote file %s: %w", rf.URL, err)
		}
		// Start background update goroutine if interval is set
		if rf.Interval > 0 {
			go updateRemoteFile(rf, m)
		}
	}

	if m.Len() > 0 {
		ds.mg = append(ds.mg, m)
	}

	for _, tag := range args.Sets {
		provider, _ := bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
		if provider == nil {
			return nil, fmt.Errorf("%s is not a DomainMatcherProvider", tag)
		}
		m := provider.GetDomainMatcher()
		ds.mg = append(ds.mg, m)
	}
	return ds, nil
}

func LoadExpsAndFiles(exps []string, fs []string, m *domain.MixMatcher[struct{}]) error {
	if err := LoadExps(exps, m); err != nil {
		return err
	}
	if err := LoadFiles(fs, m); err != nil {
		return err
	}
	return nil
}

func LoadExps(exps []string, m *domain.MixMatcher[struct{}]) error {
	for i, exp := range exps {
		if err := m.Add(exp, struct{}{}); err != nil {
			return fmt.Errorf("failed to load expression #%d %s, %w", i, exp, err)
		}
	}
	return nil
}

func LoadFiles(fs []string, m *domain.MixMatcher[struct{}]) error {
	for i, f := range fs {
		if err := LoadFile(f, m); err != nil {
			return fmt.Errorf("failed to load file #%d %s, %w", i, f, err)
		}
	}
	return nil
}

func LoadFile(f string, m *domain.MixMatcher[struct{}]) error {
	if len(f) > 0 {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}

		if err := domain.LoadFromTextReader[struct{}](m, bytes.NewReader(b), nil); err != nil {
			return err
		}
	}
	return nil
}

func LoadRemoteFile(rf RemoteFile, m *domain.MixMatcher[struct{}]) error {
	// Create directory if it doesn't exist
	if dir := filepath.Dir(rf.Path); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Download file if it doesn't exist
	if _, err := os.Stat(rf.Path); os.IsNotExist(err) {
		if err := downloadFile(rf.URL, rf.Path); err != nil {
			return err
		}
	}

	// Load the file first
	if err := LoadFile(rf.Path, m); err != nil {
		return err
	}

	// Then update it once to ensure we have the latest version
	if err := downloadFile(rf.URL, rf.Path); err != nil {
		return fmt.Errorf("failed to update remote file: %w", err)
	}

	// Reload with updated content
	return LoadFile(rf.Path, m)
}

func updateRemoteFile(rf RemoteFile, m *domain.MixMatcher[struct{}]) {
	ticker := time.NewTicker(time.Duration(rf.Interval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Create a new matcher for the updated rules
		newMatcher := domain.NewDomainMixMatcher()
		if err := downloadFile(rf.URL, rf.Path); err != nil {
			continue
		}
		if err := LoadFile(rf.Path, newMatcher); err != nil {
			continue
		}

		// Replace the old matcher's internal data with the new one
		*m = *newMatcher
	}
}

func downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
