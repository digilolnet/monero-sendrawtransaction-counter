# Monero node send_raw_transaction unique IP counting reverse proxy
This tool is designed to catch malicious reverse proxies that leech of public nodes and is used by [Chainanalysis](https://www.chainalysis.com) and probably others.

All it does is count unique IPs that hit /send_raw_transaction and /sendrawtransaction endpoints and pass the unmodified traffic to Monero node.

## Usage
Install via:
```shell
go install github.com/digilolnet/monero-sendrawtransaction-counter@latest
```

Usage:
```
Usage of monero-sendrawtransaction-counter:
  -bind string
        Bind address to listen on (default ":18081")
  -metrics-pass string
        Password for metrics endpoint (leave empty for no protection)
  -metrics-user string
        Username for metrics endpoint (leave empty for no protection)
  -upstream string
        The upstream server URL (default "http://localhost:8081")
  -use-x-forwarded
        Use X-Forwarded-For header to get client IP
```

Example:
```shell
monero-sendrawtransaction-counter -bind :18081 -upstream http://localhost:8081 -metrics-user admin -metrics-pass supersecure
```
or
```shell
~/go/bin/monero-sendrawtransaction-counter -bind :18081 -upstream http://localhost:8081 -metrics-user admin -metrics-pass supersecure
```

All the metrics are exposed in Prometheus format under the `/metrics` endpoint.

## License
Licensed under the Apache License, Version 2.0
