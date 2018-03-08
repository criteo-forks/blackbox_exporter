// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"context"
	"time"

	"gopkg.in/ldap.v2"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

// Can't do this since you can't import internal packages anymore. Would have been cool.
// type LDAPTrace struct {
// 	nettrace.Trace
// 	BindStart func()
// 	BindStop  func()
// 	// Not implemented yet
// 	// QueryStart	func()
// 	// QueryStop	func()
// }

// ProbeLDAP Probes a LDAP server and set the various metrics to their desired level
func ProbeLDAP(ctx context.Context, target string, module config.Module, registy *prometheus.Registry, logger log.Logger) bool {
	probeLDAPStatusCode := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "probe",
		Subsystem: "ldap",
		Name:      "status_code",
		Help:      "The status-code returned by LDAP server",
	})
	probeDuration := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "probe",
		Subsystem: "ldap",
		Name:      "duration",
		Help:      "The duration it took for different phase of probing",
	}, []string{"phase"})
	probeLDAPQueryResultCount := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "probe",
		Subsystem: "ldap",
		Name:      "result_count",
		Help:      "The number of entries returned by LDAP server",
	})

	connectPhase, err := probeDuration.GetMetricWithLabelValues("connect")
	if err != nil {
		level.Error(logger).Log("msg", "Error adding connect label to duration metric", "err", err)
	}

	registy.MustRegister(probeLDAPStatusCode)
	registy.MustRegister(probeDuration)
	registy.MustRegister(probeLDAPQueryResultCount)

	deadline, _ := ctx.Deadline()
	connectStart := time.Now()
	conn, err := ldap.Dial("tcp", target)
	if err != nil {
		level.Error(logger).Log("msg", "Error dialing LDAP", "err", err)
		return false
	}
	defer conn.Close()
	connectPhase.Set(time.Since(connectStart).Seconds())
	level.Info(logger).Log("msg", "Successfully connected")
	conn.SetTimeout(time.Until(deadline))

	bindPhase, err := probeDuration.GetMetricWithLabelValues("bind")
	if err != nil {
		level.Error(logger).Log("msg", "Error adding bind label to duration metric", "err", err)
		return false
	}
	bindStart := time.Now()
	_, err = conn.SimpleBind(ldap.NewSimpleBindRequest(module.LDAP.Bind.Username, module.LDAP.Bind.Password, nil))
	bindPhase.Set(time.Since(bindStart).Seconds())
	if err != nil {
		ldapError, ok := err.(*ldap.Error)
		if ok {
			probeLDAPStatusCode.Set(float64(ldapError.ResultCode))
		}
		//Not ldap.Error style error, mostly due to transport
		level.Error(logger).Log("msg", "Error during bind", "err", err)
		return false
	}
	probeLDAPStatusCode.Set(0)

	if module.LDAP.Query.DN == "" {
		return true
	}

	searchRequest := ldap.NewSearchRequest(
		module.LDAP.Query.DN, // The base dn to search
		config.LDAPScopes[module.LDAP.Query.Scope], ldap.NeverDerefAliases, -1, 0, false,
		module.LDAP.Query.Filter,
		module.LDAP.Query.Attributes,
		nil,
	)

	queryPhase, err := probeDuration.GetMetricWithLabelValues("search")
	if err != nil {
		level.Error(logger).Log("msg", "Error adding search label to duration metric", "err", err)
		return false
	}
	queryStart := time.Now()
	sr, err := conn.SearchWithPaging(searchRequest, 100)
	if err != nil {
		ldapError, ok := err.(*ldap.Error)
		if ok {
			probeLDAPStatusCode.Set(float64(ldapError.ResultCode))
		}
		//Not ldap.Error style error, mostly due to transport
		level.Error(logger).Log("msg", "Error during search", "err", err)
		return false
	}
	queryPhase.Set(time.Since(queryStart).Seconds())
	probeLDAPQueryResultCount.Set(float64(len(sr.Entries)))
	return true
}
