// Copyright (c) Giuseppe Di Terlizzi
// SPDX-License-Identifier: MIT

package exporter

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/prometheus/common/version"
)

type CheckStatus struct {
	Status   string `json:"status"`
	Progress int    `json:"progress"`
}

type ServerStatusResponse struct {
	Code           int `json:"code"`
	DetailedStatus struct {
		LoginStatus  string      `json:"login_status"`
		FeedStatus   CheckStatus `json:"feed_status"`
		DBStatus     CheckStatus `json:"db_status"`
		EngineStatus CheckStatus `json:"engine_status"`
	} `json:"detailed_status"`
	PluginSet  bool   `json:"pluginSet"`
	PluginData bool   `json:"pluginData"`
	InitLevel  int    `json:"initLevel"`
	Progress   int    `json:"progress"`
	Status     string `json:"status"`
}

type PerfStats struct {
	KbytesReceived                int         `json:"kbytes_received"`
	KbytesSent                    int         `json:"kbytes_sent"`
	AvgDNSLookupTime              int         `json:"avg_dns_lookup_time"`
	NumDNSLookups                 int         `json:"num_dns_lookups"`
	AvgRdnsLookupTime             int         `json:"avg_rdns_lookup_time"`
	NumRdnsLookups                int         `json:"num_rdns_lookups"`
	CPULoadAvg                    int         `json:"cpu_load_avg"`
	NessusCPU                     int         `json:"nessus_cpu"`
	NessusLogDiskFree             int         `json:"nessus_log_disk_free"`
	NessusLogDiskTotal            int         `json:"nessus_log_disk_total"`
	NessusDataDiskFree            int         `json:"nessus_data_disk_free"`
	NessusDataDiskTotal           int         `json:"nessus_data_disk_total"`
	PluginsCodeDbCorrupted        int         `json:"plugins_code_db_corrupted"`
	PluginsDescriptionDbCorrupted int         `json:"plugins_description_db_corrupted"`
	PluginsFailedToCompileCount   int         `json:"plugins_failed_to_compile_count"`
	TempDiskFree                  int         `json:"temp_disk_free"`
	TempDiskTotal                 int         `json:"temp_disk_total"`
	NumTCPSessions                int         `json:"num_tcp_sessions"`
	NessusVmem                    int         `json:"nessus_vmem"`
	NessusMem                     int         `json:"nessus_mem"`
	SysRAMUsed                    interface{} `json:"sys_ram_used"` // always NULL
	SysRAM                        int         `json:"sys_ram"`
	SysCores                      int         `json:"sys_cores"`
	NumHosts                      int         `json:"num_hosts"`
	NumScans                      int         `json:"num_scans"`
	Timestamp                     int         `json:"timestamp"`
}

type SettingsHealthStatsResponse struct {
	PerfStatsHistory []PerfStats `json:"perf_stats_history"`
	PerfStatsCurrent PerfStats   `json:"perf_stats_current"`
}

type ServerPropertiesResponse struct {
	Expiration             int    `json:"expiration"`
	ExpirationTime         int    `json:"expiration_time"` // days
	IPs                    int    `json:"ips"`             // Max IPs in license
	NessusType             string `json:"nessus_type"`
	NessusUIBuild          string `json:"nessus_ui_build"`
	NessusUIVersion        string `json:"nessus_ui_version"`
	Platform               string `json:"platform"`
	PluginSet              string `json:"plugin_set"`
	ScannerBackendBootTime int    `json:"scanner_backend_boottime"`
	ScannerBootTime        int    `json:"scanner_boottime"`
	ServerBuild            string `json:"server_build"`
	ServerVersion          string `json:"server_version"`
	ServerUUID             string `json:"server_uuid"`
	TemplateVersion        string `json:"template_version"`
	UsedIPCount            int    `json:"used_ip_count"`

	License struct {
		Type           string `json:"type"`
		Name           string `json:"name"`
		ExpirationDate int    `json:"expiration_date"` // Timestamp
		IPs            int    `json:"ips"`             // Max IPs in license
		ScannersUsed   int    `json:"scanners_used"`
		AgentsUsed     int    `json:"agents_used"`
	} `json:"license"`
}

type PluginsFamiliesResponse struct {
	Families []struct {
		Count int    `json:"count"`
		Name  string `json:"name"`
		ID    int    `json:"id"`
	} `json:"families"`
}

type NessusAPI interface {
	GetHealthStats() (SettingsHealthStatsResponse, error)
	GetServerProperties() (ServerPropertiesResponse, error)
	GetServerStatus() (ServerStatusResponse, error)
	GetPluginsFamilies() (PluginsFamiliesResponse, error)
}

type NessusClient struct {
	URL           string
	AccessKey     string
	SecretKey     string
	SkipTLSVerify bool
	logger        slog.Logger
}

func NewNessusClient(url string, accessKey string, secretKey string, skipTLS bool, logger slog.Logger) *NessusClient {
	return &NessusClient{
		URL:           url,
		AccessKey:     accessKey,
		SecretKey:     secretKey,
		logger:        logger,
		SkipTLSVerify: skipTLS,
	}
}

func (n *NessusClient) callNessusAPI(method string, requestURL string, responseData any) error {

	client := http.Client{}

	if n.SkipTLSVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	baseURL, err := url.Parse(n.URL)

	if err != nil {
		n.logger.Error("Error parsing Nessus URL", "url", n.URL)
		return err
	}

	req, err := http.NewRequest(method, baseURL.JoinPath(requestURL).String(), nil)

	if err != nil {
		return err
	}

	apiKey := fmt.Sprintf("accessKey=%s;secretKey=%s", n.AccessKey, n.SecretKey)

	req.Header = http.Header{
		"User-Agent":   {fmt.Sprintf("nessus_exporter/%s", version.Version)},
		"Content-Type": {"application/json"},
		"X-APIKeys":    {apiKey},
	}

	res, err := client.Do(req)

	if err != nil {
		n.logger.Error("Error making request to Nessus API", "err", err)
		return err
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)

	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		n.logger.Error("Nessus API request failed", "status", res.Status, "body", string(body))
		return fmt.Errorf("request failed: %s", res.Status)
	}

	err = json.Unmarshal(body, &responseData)

	if err != nil {
		n.logger.Error("Error unmarshalling Nessus API response", "err", err, "body", string(body))
		return err
	}

	return nil
}

func (n *NessusClient) GetHealthStats() (SettingsHealthStatsResponse, error) {

	var data SettingsHealthStatsResponse
	err := n.callNessusAPI("GET", "/settings/health/stats", &data)

	if err != nil {
		return SettingsHealthStatsResponse{}, err
	}

	return data, nil

}

func (n *NessusClient) GetServerProperties() (ServerPropertiesResponse, error) {

	var data ServerPropertiesResponse
	err := n.callNessusAPI("GET", "/server/properties", &data)

	if err != nil {
		return ServerPropertiesResponse{}, err
	}

	return data, nil

}

func (n *NessusClient) GetServerStatus() (ServerStatusResponse, error) {

	var data ServerStatusResponse
	err := n.callNessusAPI("GET", "/server/status", &data)

	if err != nil {
		return ServerStatusResponse{}, err
	}

	return data, nil

}

func (n *NessusClient) GetPluginsFamilies() (PluginsFamiliesResponse, error) {

	var data PluginsFamiliesResponse
	err := n.callNessusAPI("GET", "/plugins/families", &data)

	if err != nil {
		return PluginsFamiliesResponse{}, err
	}

	return data, nil

}
