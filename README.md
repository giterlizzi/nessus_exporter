# nessus_exporter

## Overview

`nessus_exporter` is a Prometheus exporter for Tenable® Nessus®, exposing real-time metrics such as server health, license status and utilization, Nessus version, active scans, and currently scanned hosts. These metrics enable integration with Prometheus-based monitoring and alerting systems.

## Features

- Connects to Nessus API
- Exports Nessus server statistics (health, license, version, scan)

## Installation

You can download the `nessus_exporter` from the [releases](https://github.com/giterlizzi/nessus_exporter/releases) page or install it using `go install`:

```bash
go install github.com/giterlizzi/nessus_exporter@latest
```

## Usage

```console
usage: nessus_exporter [<flags>]


Flags:
  -h, --[no-]help          Show context-sensitive help (also try --help-long and --help-man).
      --web.listen-address=":18834"  
                           Address on which to expose metrics and web interface. ($LISTEN_ADDRESS)
      --web.telemetry-path="/metrics"  
                           Path under which to expose metrics. ($TELEMETRY_PATH)
      --nessus.pid-file=NESSUS.PID-FILE  
                           Optional path to a file containing the nessusd PID for additional metrics. ($NESSUS_PID_FILE)
      --nessus.url="https://127.0.0.1:8834"  
                           URL of the Tenable(R) Nessus(R) scanner. ($NESSUS_URL)
      --[no-]nessus.tls.insecure-skip-verify  
                           Skip server certificate verification ($NESSUS_SKIP_TLS_VERIFY)
      --nessus.auth.access-key=NESSUS.AUTH.ACCESS-KEY  
                           Access Key for the Tenable(R) Nessus(R) scanner. ($NESSUS_ACCESS_KEY)
      --nessus.auth.secret-key=NESSUS.AUTH.SECRET-KEY  
                           Secret Key for the Tenable(R) Nessus(R) scanner. ($NESSUS_SECRET_KEY)
      --log.level=info     Only log messages with the given severity or above. One of: [debug, info, warn, error]
      --log.format=logfmt  Output format of log messages. One of: [logfmt, json]
      --[no-]version       Show application version.
```

| Flag                                     | Description                                                                     | Default                    |
| ---------------------------------------- | ------------------------------------------------------------------------------- | -------------------------- |
| `-h`, `--[no-]help`                      | Show context-sensitive help                                                     | —                          |
| `--web.listen-address`                   | Address on which to expose metrics and web interface                            | `":18834"`                 |
| `--web.telemetry-path`                   | Path under which to expose Prometheus metrics                                   | `"/metrics"`               |
| `--nessus.pid-file`                      | Optional path to a file containing the Nessus daemon PID for additional metrics | `""`                       |
| `--nessus.url`                           | URL of the Tenable® Nessus® scanner                                             | `"https://127.0.0.1:8834"` |
| `--[no-]nessus.tls.insecure-skip-verify` | Skip TLS certificate verification (use with caution)                            | `false`                    |
| `--nessus.auth.access-key`               | Access Key for Nessus API authentication                                        | `""`                       |
| `--nessus.auth.secret-key`               | Secret Key for Nessus API authentication                                        | `""`                       |
| `--log.level`                            | Minimum log level. One of: `debug`, `info`, `warn`, `error`                     | `"info"`                   |
| `--log.format`                           | Log output format. One of: `logfmt`, `json`                                     | `"logfmt"`                 |
| `--[no-]version`                         | Show application version and exit                                               | `false`                    |

### Environment Variables

Some command-line flags can alternatively be configured via environment variables:

| Environment Variable     | Equivalent Flag                                                |
| ------------------------ | -------------------------------------------------------------- |
| `NESSUS_URL`             | `--nessus.url`                                                 |
| `NESSUS_ACCESS_KEY`      | `--nessus.auth.access-key`                                     |
| `NESSUS_SECRET_KEY`      | `--nessus.auth.secret-key`                                     |
| `NESSUS_PID_FILE`        | `--nessus.pid-file`                                            |
| `NESSUS_SKIP_TLS_VERIFY` | `--nessus.tls.insecure-skip-verify` (set to `true` or `false`) |

Using environment variables is recommended in security-sensitive and containerized environments:

- Prevents credentials from being exposed via process list (ps, docker logs, etc.)
- Makes it easier to manage secrets via orchestration platforms (Kubernetes, Docker Compose, etc.)
- Simplifies deployment scripts and CI/CD pipelines

### Authentication

To authenticate with the Nessus API, you must generate an Access Key and Secret Key from the Nessus user interface.

[Tenable Documentation – Generate an API Key](https://docs.tenable.com/nessus/Content/GenerateAnAPIKey.htm)

Once generated, set the keys via environment variables or command-line flags:

```console
export NESSUS_ACCESS_KEY="your_access_key"
export NESSUS_SECRET_KEY="your_secret_key"
./nessus_exporter \
  [...]
```

Alternatively:

```console
./nessus_exporter \
  --nessus.auth.access-key=your_access_key \
  --nessus.auth.secret-key=your_secret_key \
  [...]
```

**NOTE** For security, it's highly recommended to use environment variables instead of passing credentials directly in the CLI.

## Configuration

### Prometheus

Add the following job to your `prometheus.yml`:

```yaml
scrape_configs:
    - job_name: 'nessus'
        static_configs:
            - targets: ['localhost:18834']
```

### Alerting Rules

`nessus_exporter` provides sample alerting rules in the [nessus_alert_rules.yml](nessus_alert_rules.yml) file.

To include these rules in your Prometheus configuration, copy the [nessus_alert_rules.yml](nessus_alert_rules.yml) file to your Prometheus configuration directory (e.g. `/etc/prometheus`) and add the following lines to your `prometheus.yml`:

```yaml
rule_files:
  - nessus_alert_rules.yml
```

| Alert                        | Description                                | Severity |
|------------------------------|--------------------------------------------|----------|
| NessusDown                   | Nessus exporter is down                    | critical |
| NessusHighCPU                | High Nessus CPU usage                      | warning  |
| NessusLowDiskSpace           | Low disk space for Nessus data directory   | warning  |
| NessusLicenseExpire          | Nessus license expires in less than 7 days | warning  |
| NessusLicenseQuotaExceeded   | Nessus IP license usage above 90%          | warning  |
| NessusScanInProgress         | Nessus scan in progress                    | info     |
| NessusPluginUpdatesAvailable | Nessus plugin updates available            | info     |
| NessusPluginSetOutdated      | Nessus plugin set is older than 30 days    | warning  |

## Exported Metrics

| Metric                       | Description                                          | Type    | Category |
| ---------------------------- | ---------------------------------------------------- | ------- | -------- |
| `nessus_exporter_build_info` | Build metadata (version, revision, Go runtime, etc.) | `gauge` | general  |
| `nessus_info`                | Nessus info (version, type, platform, plugin set)    | `gauge` | general  |
| `nessus_server_status`       | Server readiness status (check type and status)      | `gauge` | general  |
| `nessus_server_uuid`         | Server UUID                                          | `gauge` | general  |

### Health Metrics

| Metric                                           | Description                             | Type    |
| ------------------------------------------------ | --------------------------------------- | ------- |
| `nessus_health_avg_dns_lookup_time`              | Average DNS lookup time (ms)            | `gauge` |
| `nessus_health_avg_rdns_lookup_time`             | Average reverse DNS lookup time (ms)    | `gauge` |
| `nessus_health_cpu_load_avg`                     | System load average or CPU usage        | `gauge` |
| `nessus_health_kbytes_received`                  | Total KB received by Nessus             | `gauge` |
| `nessus_health_kbytes_sent`                      | Total KB sent by Nessus                 | `gauge` |
| `nessus_health_nessus_cpu`                       | CPU usage by Nessus (0–100%)            | `gauge` |
| `nessus_health_nessus_data_disk_free`            | Free disk space in data directory (MB)  | `gauge` |
| `nessus_health_nessus_data_disk_total`           | Total disk space in data directory (MB) | `gauge` |
| `nessus_health_nessus_log_disk_free`             | Free disk space in log directory (MB)   | `gauge` |
| `nessus_health_nessus_log_disk_total`            | Total disk space in log directory (MB)  | `gauge` |
| `nessus_health_nessus_mem`                       | Real memory used by Nessus (MB)         | `gauge` |
| `nessus_health_nessus_vmem`                      | Virtual memory used by Nessus (MB)      | `gauge` |
| `nessus_health_num_dns_lookups`                  | DNS lookups performed                   | `gauge` |
| `nessus_health_num_hosts`                        | Hosts currently being scanned           | `gauge` |
| `nessus_health_num_rdns_lookups`                 | Reverse DNS lookups performed           | `gauge` |
| `nessus_health_num_scans`                        | Number of running scans                 | `gauge` |
| `nessus_health_num_tcp_sessions`                 | Open TCP connections                    | `gauge` |
| `nessus_health_plugins_code_db_corrupted`        | Code plugin DB corruption status        | `gauge` |
| `nessus_health_plugins_description_db_corrupted` | Description plugin DB corruption status | `gauge` |
| `nessus_health_plugins_failed_to_compile_count`  | Failed plugin compile count             | `gauge` |
| `nessus_health_sys_cores`                        | Number of CPU cores                     | `gauge` |
| `nessus_health_sys_ram`                          | Total system RAM (MB)                   | `gauge` |
| `nessus_health_temp_disk_free`                   | Free space in temp directory (MB)       | `gauge` |
| `nessus_health_temp_disk_total`                  | Total space in temp directory (MB)      | `gauge` |

### License Metrics

| Metric                                        | Description                      | Type    |
| --------------------------------------------- | -------------------------------- | ------- |
| `nessus_license_info`                         | License info (name and type)     | `gauge` |
| `nessus_license_expiration_timestamp_seconds` | Expiration date (Unix timestamp) | `gauge` |
| `nessus_license_agents_used`                  | Number of agents using license   | `gauge` |
| `nessus_license_ips_total`                    | Total IPs allowed by license     | `gauge` |
| `nessus_license_ips_used`                     | IPs currently in use             | `gauge` |
| `nessus_license_scanners_used`                | Scanners using the license       | `gauge` |

### Scan Metrics

| Metric                            | Description                   | Type    |
| --------------------------------- | ----------------------------- | ------- |
| `nessus_scan_running_scan`        | Number of running scans       | `gauge` |
| `nessus_scan_hosts_beign_scanned` | Hosts currently being scanned | `gauge` |

### Plugins Metrics

| Metric                        | Description                                                                                                   | Type    |
| ------------------------------| ------------------------------------------------------------------------------------------------------------- | ------- |
| `nessus_plugin_set_timestamp` | Timestamp (in seconds) of the last Tenable(R) Nessus(R) plugin set update.                                    | `gauge` |
| `nessus_plugin_family`        | The total number of plugins available in each Tenable(R) Nessus(R) plugin family, labeled by the family name. | `gauge` |

## License

MIT

## Disclaimer

This project is not affiliated with, endorsed by, or sponsored by Tenable, Inc. or the Nessus product. Nessus® and Tenable® are registered trademarks of Tenable, Inc. All rights to these trademarks, names, and products belong to their respective owners.
