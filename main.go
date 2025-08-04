// Copyright (c) Giuseppe Di Terlizzi
// SPDX-License-Identifier: MIT

package main

import (
	"net/http"
	"os"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/giterlizzi/nessus_exporter/pkg/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	clientVersion "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
)

var (
	listenAddress = kingpin.Flag("web.listen-address", "Address on which to expose metrics and web interface.").Default(":18834").Envar("LISTEN_ADDRESS").String()
	metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").Envar("TELEMETRY_PATH").String()
	pidFile       = kingpin.Flag("nessus.pid-file", "Optional path to a file containing the nessusd PID for additional metrics.").Envar("NESSUS_PID_FILE").String()
	scannerURL    = kingpin.Flag("nessus.url", "URL of the Tenable(R) Nessus(R) scanner.").Default("https://127.0.0.1:8834").Envar("NESSUS_URL").String()
	skipTLSVerify = kingpin.Flag("nessus.tls.insecure-skip-verify", "Skip server certificate verification").Default("false").Envar("NESSUS_SKIP_TLS_VERIFY").Bool()
	accessKey     = kingpin.Flag("nessus.auth.access-key", "Access Key for the Tenable(R) Nessus(R) scanner.").Envar("NESSUS_ACCESS_KEY").String()
	secretKey     = kingpin.Flag("nessus.auth.secret-key", "Secret Key for the Tenable(R) Nessus(R) scanner.").Envar("NESSUS_SECRET_KEY").String()
)

func main() {

	flag.AddFlags(kingpin.CommandLine, &promslog.Config{})

	kingpin.HelpFlag.Short('h')
	kingpin.Version(version.Print("nessus_exporter"))
	kingpin.Parse()

	if err := run(); err != nil {
		os.Exit(1)
	}

}

func run() error {

	logger := promslog.New(&promslog.Config{})

	logger.Info("Starting nessus_exporter", "version", version.Info())
	logger.Info("Build context", "context", version.BuildContext())
	logger.Info("Options", "url", *scannerURL, "skipTLSVerify", *skipTLSVerify, "pidFile", *pidFile)

	nessusClient := exporter.NewNessusClient(
		*scannerURL,
		*accessKey,
		*secretKey,
		*skipTLSVerify,
		*logger,
	)

	prometheus.MustRegister(clientVersion.NewCollector("nessus_exporter"))

	nessusExporter := exporter.NewNessusCollector(nessusClient, logger)

	prometheus.MustRegister(nessusExporter)

	if *pidFile != "" {

		procExporter := collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
			PidFn:     prometheus.NewPidFileFn(*pidFile),
			Namespace: "nessusd",
		})

		prometheus.MustRegister(procExporter)

	}

	http.Handle(*metricsPath, promhttp.Handler())

	if *metricsPath != "/" && *metricsPath != "" {

		landingConfig := web.LandingConfig{
			Name:        "nessus_exporter",
			Description: "Prometheus Exporter for Tenable(R) Nessus(R) scanners",
			Version:     version.Info(),
			Links: []web.LandingLinks{
				{
					Address: *metricsPath,
					Text:    "Metrics",
				},
			},
		}

		landingPage, err := web.NewLandingPage(landingConfig)

		if err != nil {
			logger.Error("Error creating landing page", "err", err)
			return err
		}

		http.Handle("/", landingPage)

	}

	server := &http.Server{
		Addr:              *listenAddress,
		ReadHeaderTimeout: 3 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		logger.Error("Error starting HTTP server", "err", err)
		return err
	}

	return nil

}
