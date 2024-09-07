// Copyright 2024 Laurynas Četyrkinas
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	ipHitCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ip_hit_count",
			Help: "Count of hits per IP address for specific endpoints",
		},
		[]string{"endpoint", "ip"},
	)

	upstreamURLStr string
	bindAddress    string
	useXForwarded  bool
	metricsUser    string
	metricsPass    string
)

func init() {
	// Register the counter with Prometheus
	prometheus.MustRegister(ipHitCounter)
}

func main() {
	flag.StringVar(&upstreamURLStr, "upstream", "http://localhost:8081", "The upstream server URL")
	flag.StringVar(&bindAddress, "bind", ":8080", "Bind address to listen on")
	flag.BoolVar(&useXForwarded, "use-x-forwarded", false, "Use X-Forwarded-For header to get client IP")
	flag.StringVar(&metricsUser, "metrics-user", "", "Username for metrics endpoint (leave empty for no protection)")
	flag.StringVar(&metricsPass, "metrics-pass", "", "Password for metrics endpoint (leave empty for no protection)")
	flag.Parse()

	upstreamURL, err := url.Parse(upstreamURLStr)
	if err != nil {
		panic(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/send_raw_transaction" || r.URL.Path == "/sendrawtransaction" {
			handleRequest(w, r, proxy)
		} else {
			proxy.ServeHTTP(w, r)
		}
	})

	// Protect the metrics endpoint only if user and pass are provided
	if metricsUser != "" && metricsPass != "" {
		http.Handle("/metrics", basicAuth(promhttp.Handler(), metricsUser, metricsPass))
	} else {
		http.Handle("/metrics", promhttp.Handler())
	}

	log.Printf("Starting server on %s, proxying to %s\n", bindAddress, upstreamURLStr)
	if err := http.ListenAndServe(bindAddress, nil); err != nil {
		panic(err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request, proxy *httputil.ReverseProxy) {
	ip := getClientIP(r)
	endpoint := r.URL.Path
	ipHitCounter.WithLabelValues(endpoint, ip).Inc()
	proxy.ServeHTTP(w, r)
}

// getClientIP retrieves the client's IP address from the request.
func getClientIP(r *http.Request) string {
	if useXForwarded {
		// Check for X-Forwarded-For header
		xForwardedFor := r.Header.Get("X-Forwarded-For")
		if xForwardedFor != "" {
			ips := strings.Split(xForwardedFor, ",")
			return strings.TrimSpace(ips[0]) // Return the first IP in the list
		}
	}
	// Fallback to RemoteAddr if X-Forwarded-For is not present or not used
	return strings.Split(r.RemoteAddr, ":")[0]
}

// basicAuth is a middleware that protects a handler with basic authentication.
func basicAuth(h http.Handler, user, pass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != user || password != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="Protected Area"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}
