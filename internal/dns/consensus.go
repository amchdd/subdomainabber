package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	mdns "github.com/miekg/dns"
)

func (r *Resolver) ResolveConsensus(ctx context.Context, name string, qtypes ...uint16) []core.DNSConsensus {
	if r == nil || r.dohURL != "" || len(r.servers) < 2 {
		return nil
	}
	results := make([]core.DNSConsensus, 0, len(qtypes))
	for _, qtype := range qtypes {
		results = append(results, r.consensusFor(ctx, name, qtype))
	}
	return results
}

func (r *Resolver) AddressConsensus(ctx context.Context, name string) (core.DNSStatus, string) {
	if r == nil {
		return core.DNSStatusError, "DISABLED"
	}
	if !r.consensus || r.dohURL != "" || len(r.servers) < 2 {
		return r.ResolveAddressStatus(ctx, name), "DISABLED"
	}
	a := r.consensusFor(ctx, name, mdns.TypeA)
	aaaa := r.consensusFor(ctx, name, mdns.TypeAAAA)
	if a.State != "CONSENSUS" || aaaa.State != "CONSENSUS" {
		if a.State == "PROPAGATING" || aaaa.State == "PROPAGATING" {
			return core.DNSStatusError, "PROPAGATING"
		}
		if a.State == "SPLIT_HORIZON" || aaaa.State == "SPLIT_HORIZON" {
			return core.DNSStatusError, "SPLIT_HORIZON"
		}
		return core.DNSStatusError, "INCONCLUSIVE"
	}
	aStatus := consensusStatus(a.Views, a.Quorum)
	aaaaStatus := consensusStatus(aaaa.Views, aaaa.Quorum)
	if aStatus == core.DNSStatusResolved || aaaaStatus == core.DNSStatusResolved {
		return core.DNSStatusResolved, "CONSENSUS"
	}
	if aStatus == core.DNSStatusNXDomain && aaaaStatus == core.DNSStatusNXDomain {
		return core.DNSStatusNXDomain, "CONSENSUS"
	}
	if aStatus == core.DNSStatusNoData && aaaaStatus == core.DNSStatusNoData {
		return core.DNSStatusNoData, "CONSENSUS"
	}
	return core.DNSStatusError, "INCONCLUSIVE"
}

func (r *Resolver) consensusFor(ctx context.Context, name string, qtype uint16) core.DNSConsensus {
	views := make([]core.DNSView, len(r.servers))
	var wait sync.WaitGroup
	for index, server := range r.servers {
		index, server := index, server
		wait.Add(1)
		go func() {
			defer wait.Done()
			views[index] = r.resolveView(ctx, server, name, qtype)
		}()
	}
	wait.Wait()
	quorum := len(views)/2 + 1
	state := consensusState(views, quorum)
	return core.DNSConsensus{QueryType: mdns.TypeToString[qtype], State: state, Quorum: quorum, Views: views}
}

func (r *Resolver) resolveView(ctx context.Context, server, name string, qtype uint16) core.DNSView {
	view := core.DNSView{Resolver: server, Status: core.DNSStatusError}
	if err := r.wait(ctx); err != nil {
		return view
	}
	message := new(mdns.Msg)
	message.SetQuestion(mdns.Fqdn(name), qtype)
	message.RecursionDesired = true
	started := time.Now()
	response, _, err := r.client.ExchangeContext(ctx, message, server)
	view.LatencyMs = time.Since(started).Milliseconds()
	if err != nil {
		view.Status = statusFromError(err)
		return view
	}
	view.Status = responseStatus(response, qtype)
	view.Answers, view.TTL = answerSet(response, qtype)
	return view
}

func statusFromError(err error) core.DNSStatus {
	var networkError net.Error
	if errorsAsNet(err, &networkError) && networkError.Timeout() {
		return core.DNSStatusTimeout
	}
	return core.DNSStatusError
}

func answerSet(message *mdns.Msg, qtype uint16) ([]string, uint32) {
	if message == nil {
		return nil, 0
	}
	var answers []string
	var ttl uint32
	for _, answer := range message.Answer {
		if answer.Header().Rrtype != qtype && answer.Header().Rrtype != mdns.TypeCNAME {
			continue
		}
		if ttl == 0 || answer.Header().Ttl < ttl {
			ttl = answer.Header().Ttl
		}
		answers = append(answers, consensusAnswer(answer))
	}
	sort.Strings(answers)
	return answers, ttl
}

func consensusAnswer(answer mdns.RR) string {
	switch record := answer.(type) {
	case *mdns.A:
		return "a:" + record.A.String()
	case *mdns.AAAA:
		return "aaaa:" + record.AAAA.String()
	case *mdns.CNAME:
		return "cname:" + strings.ToLower(strings.TrimSuffix(record.Target, "."))
	default:
		return strings.ToLower(answer.String())
	}
}

func consensusState(views []core.DNSView, quorum int) string {
	counts := make(map[string]int)
	valid := 0
	positive, negative := false, false
	for _, view := range views {
		if view.Status == core.DNSStatusError || view.Status == core.DNSStatusTimeout || view.Status == core.DNSStatusServFail {
			continue
		}
		valid++
		key := fmt.Sprintf("%s|%s", view.Status, strings.Join(view.Answers, "\n"))
		counts[key]++
		if view.Status == core.DNSStatusResolved {
			positive = true
		}
		if view.Status == core.DNSStatusNXDomain || view.Status == core.DNSStatusNoData {
			negative = true
		}
	}
	for _, count := range counts {
		if count >= quorum {
			return "CONSENSUS"
		}
	}
	if valid < quorum {
		return "INCONCLUSIVE"
	}
	if positive && negative {
		return "PROPAGATING"
	}
	return "SPLIT_HORIZON"
}

func consensusStatus(views []core.DNSView, quorum int) core.DNSStatus {
	counts := make(map[core.DNSStatus]int)
	for _, view := range views {
		counts[view.Status]++
	}
	for status, count := range counts {
		if count >= quorum {
			return status
		}
	}
	return core.DNSStatusError
}
