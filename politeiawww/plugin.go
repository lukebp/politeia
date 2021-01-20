// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"time"

	pd "github.com/decred/politeia/politeiad/api/v1"
)

// pluginSetting is a structure that holds the key-value pairs of a plugin
// setting.
type pluginSetting struct {
	Key   string
	Value string
}

// plugin describes a plugin and its settings.
type plugin struct {
	ID       string          // Identifier
	Version  string          // Version
	Settings []pluginSetting // Settings
}

func convertPluginFromPD(p pd.Plugin) plugin {
	ps := make([]pluginSetting, 0, len(p.Settings))
	for _, v := range p.Settings {
		ps = append(ps, pluginSetting{
			Key:   v.Key,
			Value: v.Value,
		})
	}
	return plugin{
		ID:       p.ID,
		Version:  p.Version,
		Settings: ps,
	}
}

// getPluginInventory returns the politeiad plugin inventory. If a politeiad
// connection cannot be made, the call will be retried every 5 seconds for up
// to 1000 tries.
func (p *politeiawww) getPluginInventory() ([]plugin, error) {
	// Attempt to fetch the plugin inventory from politeiad until
	// either it is successful or the maxRetries has been exceeded.
	var (
		done          bool
		maxRetries    = 1000
		sleepInterval = 5 * time.Second
		plugins       = make([]plugin, 0, 16)
		ctx           = context.Background()
	)
	for retries := 0; !done; retries++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if retries == maxRetries {
			return nil, fmt.Errorf("max retries exceeded")
		}

		pi, err := p.politeiad.PluginInventory(ctx)
		if err != nil {
			log.Infof("cannot get politeiad plugin inventory: %v: retry in %v",
				err, sleepInterval)
			time.Sleep(sleepInterval)
			continue
		}
		for _, v := range pi {
			plugins = append(plugins, convertPluginFromPD(v))
		}

		done = true
	}

	return plugins, nil
}
