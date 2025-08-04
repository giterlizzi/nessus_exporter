// Copyright (c) Giuseppe Di Terlizzi
// SPDX-License-Identifier: MIT

package exporter

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/promslog"
)

type mockNessusClient struct{}

func (m *mockNessusClient) GetHealthStats() (SettingsHealthStatsResponse, error) {
	return SettingsHealthStatsResponse{}, nil
}

func (m *mockNessusClient) GetServerProperties() (ServerPropertiesResponse, error) {
	return ServerPropertiesResponse{
		ServerUUID: "00000000-0000-0000-0000-0000000000000000000000000000",
	}, nil
}

func (m *mockNessusClient) GetServerStatus() (ServerStatusResponse, error) {
	return ServerStatusResponse{}, nil
}

func (m *mockNessusClient) GetPluginsFamilies() (PluginsFamiliesResponse, error) {
	return PluginsFamiliesResponse{}, nil
}

func TestNessusCollector(t *testing.T) {

	mockClient := &mockNessusClient{}
	collector := NewNessusCollector(mockClient, promslog.New(&promslog.Config{}))

	reg := prometheus.NewRegistry()
	reg.MustRegister(collector)

	expected := `
# HELP nessus_server_uuid Tenable(R) Nessus(R) server UUID
# TYPE nessus_server_uuid gauge
nessus_server_uuid{uuid="00000000-0000-0000-0000-0000000000000000000000000000"} 1
`

	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "nessus_server_uuid"); err != nil {
		t.Errorf("unexpected collecting result: %s", err)
	}

}
