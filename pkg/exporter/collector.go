// Copyright (c) Giuseppe Di Terlizzi
// SPDX-License-Identifier: MIT

package exporter

import (
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type NessusCollector struct {
	nessus NessusAPI
	logger *slog.Logger

	avgDnsLookupTime              *prometheus.Desc
	avgRdnsLookupTime             *prometheus.Desc
	cpuLoadAvg                    *prometheus.Desc
	kbytesReceived                *prometheus.Desc
	kbytesSent                    *prometheus.Desc
	nessusCpu                     *prometheus.Desc
	nessusDataDiskFree            *prometheus.Desc
	nessusDataDiskTotal           *prometheus.Desc
	nessusLogDiskFree             *prometheus.Desc
	nessusLogDiskTotal            *prometheus.Desc
	nessusMem                     *prometheus.Desc
	nessusVmem                    *prometheus.Desc
	numDnsLookups                 *prometheus.Desc
	numHosts                      *prometheus.Desc
	numRdnsLookups                *prometheus.Desc
	numScans                      *prometheus.Desc
	numTcpSessions                *prometheus.Desc
	pluginsCodeDbCorrupted        *prometheus.Desc
	pluginsDescriptionDbCorrupted *prometheus.Desc
	pluginsFailedToCompileCount   *prometheus.Desc
	sysCores                      *prometheus.Desc
	sysRam                        *prometheus.Desc
	tempDiskFree                  *prometheus.Desc
	tempDiskTotal                 *prometheus.Desc

	nessusInfo  *prometheus.Desc
	licenseInfo *prometheus.Desc

	scanRunningScan       *prometheus.Desc
	scanHostsBeingScanned *prometheus.Desc

	serverStatus *prometheus.Desc
	serverUUID   *prometheus.Desc

	licenseAgentsUsed     *prometheus.Desc
	licenseExpirationDate *prometheus.Desc
	licenseIPsTotal       *prometheus.Desc
	licenseIPsUsed        *prometheus.Desc
	licenseScannersUsed   *prometheus.Desc

	pluginSetTimestamp *prometheus.Desc
	pluginFamily       *prometheus.Desc
}

var healthMetricsDesc = map[string]string{
	"avg_dns_lookup_time":              "The average amount of time (in milliseconds) it takes to perform a DNS lookup on detected hosts.",
	"avg_rdns_lookup_time":             "The average amount of time (in milliseconds) it takes to perform a reverse DNS lookup on detected hosts.",
	"cpu_load_avg":                     "On Unix this is the \"load average\" provided by the operating system. On Windows this is the current CPU usage (see also \"nessus_cpu\").",
	"kbytes_received":                  "The amount of data (in kilobytes) received by Nessus.",
	"kbytes_sent":                      "The amount of data (in kilobytes) sent by Nessus.",
	"nessus_cpu":                       "A normalized (0-100) value for the percentage of total system CPU available across all cores that is being used by Nessus.",
	"nessus_data_disk_free":            "The amount of free disk space (in megabytes) for the configuration directory.",
	"nessus_data_disk_total":           "The total disk size (in megabytes) for the configuration directory.",
	"nessus_log_disk_free":             "The amount of free disk space (in megabytes) for the \"log\" directory.",
	"nessus_log_disk_total":            "The total disk size (in megabytes) for the \"log\" directory.",
	"nessus_mem":                       "The total amount of real memory (in megabytes) currently in use by Nessus.",
	"nessus_vmem":                      "The total amount of virtual memory (in megabytes) currently in use by Nessus.",
	"num_dns_lookups":                  "The number of DNS lookups performed by Nessus.",
	"num_hosts":                        "The current number of hosts that are actively being scanned.",
	"num_rdns_lookups":                 "The number of reverse DNS lookups performed by Nessus.",
	"num_scans":                        "The number of actively running scans.",
	"num_tcp_sessions":                 "The number of open TCP connections at the time of this sampling.",
	"plugins_code_db_corrupted":        "",
	"plugins_description_db_corrupted": "",
	"plugins_failed_to_compile_count":  "",
	"sys_cores":                        "The total number of CPU cores available on the device, as reported by the operating system.",
	"sys_ram":                          "The total amount of RAM available on the device, as reported by the operating system.",
	"temp_disk_free":                   "The amount of free disk space (in megabytes) for the system \"temp\" directory (%TEMP% or $TMPDIR or /tmp).",
	"temp_disk_total":                  "The total disk size (in megabytes) for the system \"temp\" directory (%TEMP% or $TMPDIR or /tmp).",
}

var licenseMetricsDesc = map[string]string{
	"expiration_timestamp_seconds": "The expiration date of the license for the Tenable(R) Nessus(R) scanner, in Unix timestamp format.",
	"ips_total":                    "The number of IPs allowed by the license for the Tenable(R) Nessus(R) scanner.",
	"scanners_used":                "The number of scanners currently using the license for the Tenable(R) Nessus(R) scanner.",
	"agents_used":                  "The number of agents currently using the license for the Tenable(R) Nessus(R) scanner.",
	"ips_used":                     "The number of IPs currently using the license for the Tenable(R) Nessus(R) scanner.",
}

func NewNessusCollector(n NessusAPI, logger *slog.Logger) *NessusCollector {

	return &NessusCollector{
		nessus: n,
		logger: logger,

		// Nessus performance metrics
		avgDnsLookupTime:              prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "avg_dns_lookup_time"), healthMetricsDesc["avg_dns_lookup_time"], nil, nil),
		avgRdnsLookupTime:             prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "avg_rdns_lookup_time"), healthMetricsDesc["avg_rdns_lookup_time"], nil, nil),
		cpuLoadAvg:                    prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "cpu_load_avg"), healthMetricsDesc["cpu_load_avg"], nil, nil),
		kbytesReceived:                prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "kbytes_received"), healthMetricsDesc["kbytes_received"], nil, nil),
		kbytesSent:                    prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "kbytes_sent"), healthMetricsDesc["kbytes_sent"], nil, nil),
		nessusCpu:                     prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "nessus_cpu"), healthMetricsDesc["nessus_cpu"], nil, nil),
		nessusDataDiskFree:            prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "nessus_data_disk_free"), healthMetricsDesc["nessus_data_disk_free"], nil, nil),
		nessusDataDiskTotal:           prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "nessus_data_disk_total"), healthMetricsDesc["nessus_data_disk_total"], nil, nil),
		nessusLogDiskFree:             prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "nessus_log_disk_free"), healthMetricsDesc["nessus_log_disk_free"], nil, nil),
		nessusLogDiskTotal:            prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "nessus_log_disk_total"), healthMetricsDesc["nessus_log_disk_total"], nil, nil),
		nessusMem:                     prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "nessus_mem"), healthMetricsDesc["nessus_mem"], nil, nil),
		nessusVmem:                    prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "nessus_vmem"), healthMetricsDesc["nessus_vmem"], nil, nil),
		numDnsLookups:                 prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "num_dns_lookups"), healthMetricsDesc["num_dns_lookups"], nil, nil),
		numHosts:                      prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "num_hosts"), healthMetricsDesc["num_hosts"], nil, nil),
		numRdnsLookups:                prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "num_rdns_lookups"), healthMetricsDesc["num_rdns_lookups"], nil, nil),
		numScans:                      prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "num_scans"), healthMetricsDesc["num_scans"], nil, nil),
		numTcpSessions:                prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "num_tcp_sessions"), healthMetricsDesc["num_tcp_sessions"], nil, nil),
		pluginsCodeDbCorrupted:        prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "plugins_code_db_corrupted"), healthMetricsDesc["plugins_code_db_corrupted"], nil, nil),
		pluginsDescriptionDbCorrupted: prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "plugins_description_db_corrupted"), healthMetricsDesc["plugins_description_db_corrupted"], nil, nil),
		pluginsFailedToCompileCount:   prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "plugins_failed_to_compile_count"), healthMetricsDesc["plugins_failed_to_compile_count"], nil, nil),
		sysCores:                      prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "sys_cores"), healthMetricsDesc["sys_cores"], nil, nil),
		sysRam:                        prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "sys_ram"), healthMetricsDesc["sys_ram"], nil, nil),
		tempDiskFree:                  prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "temp_disk_free"), healthMetricsDesc["temp_disk_free"], nil, nil),
		tempDiskTotal:                 prometheus.NewDesc(prometheus.BuildFQName("nessus", "health", "temp_disk_total"), healthMetricsDesc["temp_disk_total"], nil, nil),

		// Scan information
		scanRunningScan:       prometheus.NewDesc(prometheus.BuildFQName("nessus", "scan", "running_scan"), healthMetricsDesc["num_scans"], nil, nil),
		scanHostsBeingScanned: prometheus.NewDesc(prometheus.BuildFQName("nessus", "scan", "hosts_beign_scanned"), healthMetricsDesc["num_hosts"], nil, nil),

		// Nessus information
		nessusInfo: prometheus.NewDesc(
			prometheus.BuildFQName("nessus", "", "info"),
			"A metric with a constant '1' value with Tenable(R) Nessus(R) information (version, type, platform, plugin set).",
			[]string{"version", "type", "platform", "plugin_set"}, nil,
		),

		// Nessus license information
		licenseAgentsUsed:     prometheus.NewDesc(prometheus.BuildFQName("nessus", "license", "agents_used"), licenseMetricsDesc["agents_used"], nil, nil),
		licenseExpirationDate: prometheus.NewDesc(prometheus.BuildFQName("nessus", "license", "expiration_timestamp_seconds"), licenseMetricsDesc["expiration_timestamp_seconds"], nil, nil),
		licenseIPsTotal:       prometheus.NewDesc(prometheus.BuildFQName("nessus", "license", "ips_total"), licenseMetricsDesc["ips_total"], nil, nil),
		licenseIPsUsed:        prometheus.NewDesc(prometheus.BuildFQName("nessus", "license", "ips_used"), licenseMetricsDesc["ips_used"], nil, nil),
		licenseScannersUsed:   prometheus.NewDesc(prometheus.BuildFQName("nessus", "license", "scanners_used"), licenseMetricsDesc["scanners_used"], nil, nil),

		licenseInfo: prometheus.NewDesc(
			prometheus.BuildFQName("nessus", "license", "info"),
			"A metric with a constant '1' value with Tenable(R) Nessus(R) license information (name and type).",
			[]string{"name", "type"}, nil,
		),

		// Nessus server status
		serverStatus: prometheus.NewDesc(prometheus.BuildFQName("nessus", "server", "status"), "Tenable(R) Nessus(R) server status (check, status and progress)", []string{"check", "status"}, nil),
		serverUUID:   prometheus.NewDesc(prometheus.BuildFQName("nessus", "server", "uuid"), "Tenable(R) Nessus(R) server UUID", []string{"uuid"}, nil),

		// Plugin
		pluginSetTimestamp: prometheus.NewDesc(prometheus.BuildFQName("nessus", "plugin", "set_timestamp_seconds"), "Timestamp (in seconds) of the last Tenable(R) Nessus(R) plugin set update.", nil, nil),

		pluginFamily: prometheus.NewDesc(
			prometheus.BuildFQName("nessus", "plugin", "family"),
			"The total number of plugins available in each Tenable(R) Nessus(R) plugin family, labeled by the family name.",
			[]string{"name"}, nil,
		),
	}

}

func (c *NessusCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.avgDnsLookupTime
	ch <- c.avgRdnsLookupTime
	ch <- c.cpuLoadAvg
	ch <- c.kbytesReceived
	ch <- c.kbytesSent
	ch <- c.nessusCpu
	ch <- c.nessusDataDiskFree
	ch <- c.nessusDataDiskTotal
	ch <- c.nessusLogDiskFree
	ch <- c.nessusLogDiskTotal
	ch <- c.nessusMem
	ch <- c.nessusVmem
	ch <- c.numDnsLookups
	ch <- c.numHosts
	ch <- c.numRdnsLookups
	ch <- c.numScans
	ch <- c.numTcpSessions
	ch <- c.pluginsCodeDbCorrupted
	ch <- c.pluginsDescriptionDbCorrupted
	ch <- c.pluginsFailedToCompileCount
	ch <- c.sysCores
	ch <- c.sysRam
	ch <- c.tempDiskFree
	ch <- c.tempDiskTotal

	ch <- c.nessusInfo
	ch <- c.licenseInfo

	ch <- c.scanRunningScan
	ch <- c.scanHostsBeingScanned

	ch <- c.serverStatus
	ch <- c.serverUUID

	ch <- c.licenseExpirationDate
	ch <- c.licenseIPsTotal
	ch <- c.licenseIPsUsed
	ch <- c.licenseScannersUsed
	ch <- c.licenseAgentsUsed

	ch <- c.pluginSetTimestamp
	ch <- c.pluginFamily
}

func (c *NessusCollector) Collect(ch chan<- prometheus.Metric) {

	healthStats, err := c.nessus.GetHealthStats()
	if err != nil {
		c.logger.Error("Error collecting metrics from Nessus API", "err", err)
		return
	}

	serverProperties, err := c.nessus.GetServerProperties()
	if err != nil {
		c.logger.Error("Error collecting server properties from Nessus API", "err", err)
		return
	}

	serverStatus, err := c.nessus.GetServerStatus()
	if err != nil {
		c.logger.Error("Error collecting server status from Nessus API", "err", err)
		return
	}

	pluginFamilies, err := c.nessus.GetPluginsFamilies()
	if err != nil {
		c.logger.Error("Error collecting plugins families from Nessus API", "err", err)
		return
	}

	// Health single value
	ch <- prometheus.MustNewConstMetric(c.avgDnsLookupTime, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.AvgDNSLookupTime))
	ch <- prometheus.MustNewConstMetric(c.avgRdnsLookupTime, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.AvgRdnsLookupTime))
	ch <- prometheus.MustNewConstMetric(c.cpuLoadAvg, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.CPULoadAvg))
	ch <- prometheus.MustNewConstMetric(c.kbytesReceived, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.KbytesReceived))
	ch <- prometheus.MustNewConstMetric(c.kbytesSent, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.KbytesSent))
	ch <- prometheus.MustNewConstMetric(c.nessusCpu, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NessusCPU))
	ch <- prometheus.MustNewConstMetric(c.nessusDataDiskFree, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NessusDataDiskFree))
	ch <- prometheus.MustNewConstMetric(c.nessusDataDiskTotal, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NessusDataDiskFree))
	ch <- prometheus.MustNewConstMetric(c.nessusLogDiskFree, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NessusLogDiskFree))
	ch <- prometheus.MustNewConstMetric(c.nessusLogDiskTotal, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NessusLogDiskTotal))
	ch <- prometheus.MustNewConstMetric(c.nessusMem, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NessusMem))
	ch <- prometheus.MustNewConstMetric(c.nessusVmem, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NessusVmem))
	ch <- prometheus.MustNewConstMetric(c.numDnsLookups, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NumDNSLookups))
	ch <- prometheus.MustNewConstMetric(c.numHosts, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NumHosts))
	ch <- prometheus.MustNewConstMetric(c.numRdnsLookups, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NumRdnsLookups))
	ch <- prometheus.MustNewConstMetric(c.numScans, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NumScans))
	ch <- prometheus.MustNewConstMetric(c.numTcpSessions, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NumTCPSessions))
	ch <- prometheus.MustNewConstMetric(c.pluginsCodeDbCorrupted, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.PluginsCodeDbCorrupted))
	ch <- prometheus.MustNewConstMetric(c.pluginsDescriptionDbCorrupted, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.PluginsDescriptionDbCorrupted))
	ch <- prometheus.MustNewConstMetric(c.pluginsFailedToCompileCount, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.PluginsFailedToCompileCount))
	ch <- prometheus.MustNewConstMetric(c.sysCores, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.SysCores))
	ch <- prometheus.MustNewConstMetric(c.sysRam, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.SysRAM))
	ch <- prometheus.MustNewConstMetric(c.tempDiskFree, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.TempDiskFree))
	ch <- prometheus.MustNewConstMetric(c.tempDiskTotal, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.TempDiskTotal))

	// License
	licenseInformation := serverProperties.License

	ch <- prometheus.MustNewConstMetric(c.licenseInfo, prometheus.GaugeValue, 1, licenseInformation.Name, licenseInformation.Type)
	ch <- prometheus.MustNewConstMetric(c.licenseExpirationDate, prometheus.GaugeValue, float64(licenseInformation.ExpirationDate))
	ch <- prometheus.MustNewConstMetric(c.licenseIPsTotal, prometheus.GaugeValue, float64(licenseInformation.IPs))
	ch <- prometheus.MustNewConstMetric(c.licenseIPsUsed, prometheus.GaugeValue, float64(serverProperties.UsedIPCount))
	ch <- prometheus.MustNewConstMetric(c.licenseScannersUsed, prometheus.GaugeValue, float64(licenseInformation.ScannersUsed))
	ch <- prometheus.MustNewConstMetric(c.licenseAgentsUsed, prometheus.GaugeValue, float64(licenseInformation.AgentsUsed))

	// Nessus information
	ch <- prometheus.MustNewConstMetric(c.nessusInfo, prometheus.GaugeValue, 1, serverProperties.NessusUIVersion, serverProperties.NessusType, serverProperties.Platform, serverProperties.PluginSet)

	// Server status
	ch <- prometheus.MustNewConstMetric(c.serverStatus, prometheus.GaugeValue, float64(serverStatus.Progress), "global", serverStatus.Status)
	ch <- prometheus.MustNewConstMetric(c.serverStatus, prometheus.GaugeValue, float64(serverStatus.DetailedStatus.EngineStatus.Progress), "engine", serverStatus.DetailedStatus.EngineStatus.Status)
	ch <- prometheus.MustNewConstMetric(c.serverStatus, prometheus.GaugeValue, float64(serverStatus.DetailedStatus.DBStatus.Progress), "db", serverStatus.DetailedStatus.DBStatus.Status)
	ch <- prometheus.MustNewConstMetric(c.serverStatus, prometheus.GaugeValue, float64(serverStatus.DetailedStatus.FeedStatus.Progress), "feed", serverStatus.DetailedStatus.FeedStatus.Status)

	// Server UUID
	ch <- prometheus.MustNewConstMetric(c.serverUUID, prometheus.GaugeValue, 1, serverProperties.ServerUUID)

	// Scan info
	ch <- prometheus.MustNewConstMetric(c.scanRunningScan, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NumScans))
	ch <- prometheus.MustNewConstMetric(c.scanHostsBeingScanned, prometheus.GaugeValue, float64(healthStats.PerfStatsCurrent.NumHosts))

	// Plugin
	pluginSetTime, _ := time.Parse("200601021504", serverProperties.PluginSet)
	pluginSetTimestamp := pluginSetTime.Unix()

	ch <- prometheus.MustNewConstMetric(c.pluginSetTimestamp, prometheus.GaugeValue, float64(pluginSetTimestamp))

	for _, family := range pluginFamilies.Families {
		ch <- prometheus.MustNewConstMetric(c.pluginFamily, prometheus.GaugeValue, float64(family.Count), family.Name)
	}

}
