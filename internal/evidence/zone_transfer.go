package evidence

import (
	"context"
	"strings"
	"sync"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"golang.org/x/sync/singleflight"
)

type ZoneTransferCollector struct {
	resolver zoneTransferResolver
	cache    sync.Map
	group    singleflight.Group
}

type zoneTransferResult struct {
	allowed    bool
	nameserver string
}

type zoneTransferResolver interface {
	FindAuthoritativeZone(context.Context, string) (dns.AuthoritativeZone, error)
	AttemptAXFR(context.Context, string, string) (bool, error)
}

func NewZoneTransferCollector(resolver zoneTransferResolver) *ZoneTransferCollector {
	return &ZoneTransferCollector{resolver: resolver}
}

func (c *ZoneTransferCollector) Name() string { return "ZoneTransfer" }

func (c *ZoneTransferCollector) BeginBatch() {
	c.cache = sync.Map{}
	c.group = singleflight.Group{}
}

func (c *ZoneTransferCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector("AXFR")
	zone := ""
	var nameservers []string
	if analysis.Delegation != nil {
		zone = analysis.Delegation.Zone
		nameservers = analysis.Delegation.DelegatedNameservers
	}
	if zone == "" || len(nameservers) == 0 {
		zoneInfo, err := c.resolver.FindAuthoritativeZone(ctx, analysis.Host)
		if err != nil {
			return nil
		}
		zone, nameservers = zoneInfo.Zone, zoneInfo.Nameservers
	}
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if zone == "" {
		return nil
	}

	result, err := c.resultForZone(ctx, zone, uniqueNames(nameservers))
	if err != nil || !result.allowed {
		return nil
	}
	analysis.AddEvidence(core.Evidence{
		Type: "DNS_AXFR_ALLOWED", Source: "ZoneTransfer",
		Description: "O servidor NS " + result.nameserver + " permitiu a transferência da zona autoritativa " + zone,
		Weight:      40, Confidence: 100,
		Metadata: map[string]string{"zone": zone, "nameserver": result.nameserver, "category": "exposure"},
	})
	return nil
}

func (c *ZoneTransferCollector) resultForZone(ctx context.Context, zone string, nameservers []string) (zoneTransferResult, error) {
	if cached, ok := c.cache.Load(zone); ok {
		return cached.(zoneTransferResult), nil
	}

	for attempt := 0; attempt < 2; attempt++ {
		value, err, _ := c.group.Do(zone, func() (interface{}, error) {
			if cached, ok := c.cache.Load(zone); ok {
				return cached.(zoneTransferResult), nil
			}
			result := zoneTransferResult{}
			for _, nameserver := range nameservers {
				success, transferErr := c.resolver.AttemptAXFR(ctx, zone, nameserver)
				if transferErr == nil && success {
					result.allowed = true
					result.nameserver = nameserver
					break
				}
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			c.cache.Store(zone, result)
			return result, nil
		})
		if err == nil {
			return value.(zoneTransferResult), nil
		}
		if ctx.Err() != nil {
			return zoneTransferResult{}, ctx.Err()
		}
	}
	return zoneTransferResult{}, context.Canceled
}
