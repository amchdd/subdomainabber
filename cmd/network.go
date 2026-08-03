package cmd

import (
	"fmt"
	"net/http"
	"time"

	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/netclient"
	"github.com/amchdd/subdomainabber/pkg/config"
)

func configureResolverDoH(resolver *dns.Resolver, cfg *config.Config) error {
	if resolver == nil || cfg == nil || cfg.DoH == "" {
		return nil
	}
	client, err := netclient.NewScopedClient(time.Duration(cfg.Timeout)*time.Second, cfg.Proxy, nil)
	if err != nil {
		return fmt.Errorf("configurando o cliente DoH: %w", err)
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resolver.SetDoH(cfg.DoH)
	resolver.SetDoHClient(client)
	return nil
}
