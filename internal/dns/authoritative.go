package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/amchdd/subdomainabber/internal/core"
	mdns "github.com/miekg/dns"
)

var CommonSRVOwners = []string{
	"_sip._tcp",
	"_sips._tcp",
	"_autodiscover._tcp",
	"_xmpp-client._tcp",
	"_xmpp-server._tcp",
	"_minecraft._tcp",
}

type AuthoritativeZone struct {
	Zone                     string
	ParentZone               string
	Nameservers              []string
	ParentNameservers        []string
	ParentHasDS              bool
	ParentDSChecked          bool
	ParentDelegationVerified bool
	Glue                     map[string][]string
}

// ResolveStatus retorna o resultado de uma consulta no nível do protocolo.
// Intencionalmente, não infere NXDOMAIN de mensagens localizadas de erro de transporte.
func (r *Resolver) ResolveStatus(ctx context.Context, name string, qtype uint16) (core.DNSStatus, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(name), qtype)
	msg.RecursionDesired = true
	resp, err := r.exchange(ctx, msg)
	if err != nil {
		var netErr net.Error
		if errorsAsNet(err, &netErr) && netErr.Timeout() {
			return core.DNSStatusTimeout, err
		}
		return core.DNSStatusError, err
	}
	return responseStatus(resp, qtype), nil
}

func errorsAsNet(err error, target *net.Error) bool {
	for err != nil {
		if candidate, ok := err.(net.Error); ok {
			*target = candidate
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if wrapped, ok := err.(unwrapper); ok {
			err = wrapped.Unwrap()
		} else {
			break
		}
	}
	return false
}

func responseStatus(resp *mdns.Msg, qtype uint16) core.DNSStatus {
	if resp == nil {
		return core.DNSStatusError
	}
	switch resp.Rcode {
	case mdns.RcodeNameError:
		return core.DNSStatusNXDomain
	case mdns.RcodeServerFailure:
		return core.DNSStatusServFail
	case mdns.RcodeRefused:
		return core.DNSStatusRefused
	case mdns.RcodeSuccess:
		for _, answer := range resp.Answer {
			if answer.Header().Rrtype == qtype {
				return core.DNSStatusResolved
			}
		}
		return core.DNSStatusNoData
	default:
		return core.DNSStatusError
	}
}

func (r *Resolver) ResolveAddressStatus(ctx context.Context, name string) core.DNSStatus {
	aStatus, _ := r.ResolveStatus(ctx, name, mdns.TypeA)
	if aStatus == core.DNSStatusResolved {
		return aStatus
	}
	aaaaStatus, _ := r.ResolveStatus(ctx, name, mdns.TypeAAAA)
	if aaaaStatus == core.DNSStatusResolved {
		return aaaaStatus
	}
	if aStatus == core.DNSStatusTimeout || aaaaStatus == core.DNSStatusTimeout {
		return core.DNSStatusTimeout
	}
	if aStatus == core.DNSStatusServFail || aaaaStatus == core.DNSStatusServFail {
		return core.DNSStatusServFail
	}
	if aStatus == core.DNSStatusRefused || aaaaStatus == core.DNSStatusRefused {
		return core.DNSStatusRefused
	}
	if aStatus == core.DNSStatusError || aaaaStatus == core.DNSStatusError {
		return core.DNSStatusError
	}
	if aStatus == core.DNSStatusNXDomain && aaaaStatus == core.DNSStatusNXDomain {
		return core.DNSStatusNXDomain
	}
	if aStatus == core.DNSStatusNoData && aaaaStatus == core.DNSStatusNoData {
		return core.DNSStatusNoData
	}
	// NXDOMAIN descreve a inexistência do nome, não apenas de uma família de
	// endereços. Uma resposta NXDOMAIN contradita por NODATA é inconclusiva.
	return core.DNSStatusError
}

func (r *Resolver) ResolveTXTWithStatus(ctx context.Context, name string) ([]string, core.DNSStatus, error) {
	status, err := r.ResolveStatus(ctx, name, mdns.TypeTXT)
	if err != nil || status != core.DNSStatusResolved {
		return nil, status, err
	}
	values, err := r.ResolveTXT(ctx, name)
	return values, status, err
}

func (r *Resolver) ResolveSRVRecords(ctx context.Context, owner string) ([]core.SRVRecord, core.DNSStatus, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(owner), mdns.TypeSRV)
	msg.RecursionDesired = true
	resp, err := r.exchange(ctx, msg)
	if err != nil {
		return nil, core.DNSStatusError, err
	}
	status := responseStatus(resp, mdns.TypeSRV)
	var records []core.SRVRecord
	for _, answer := range resp.Answer {
		if srv, ok := answer.(*mdns.SRV); ok {
			records = append(records, core.SRVRecord{
				Owner:    strings.TrimSuffix(strings.ToLower(srv.Hdr.Name), "."),
				Priority: srv.Priority,
				Weight:   srv.Weight,
				Port:     srv.Port,
				Target:   strings.TrimSuffix(strings.ToLower(srv.Target), "."),
			})
		}
	}
	return records, status, nil
}

func (r *Resolver) DiscoverCommonSRV(ctx context.Context, domain string, owners []string) ([]core.SRVRecord, error) {
	if len(owners) == 0 {
		owners = CommonSRVOwners
	}
	var all []core.SRVRecord
	for _, prefix := range owners {
		owner := strings.TrimSuffix(prefix, ".") + "." + strings.TrimSuffix(domain, ".")
		records, _, err := r.ResolveSRVRecords(ctx, owner)
		if err == nil {
			all = append(all, records...)
		}
	}
	return all, nil
}

// FindAuthoritativeZone descobre o corte de zona SOA/NS real de um host em vez de
// presumir que seu domínio registrável seja o ápice da zona.
func (r *Resolver) FindAuthoritativeZone(ctx context.Context, host string) (AuthoritativeZone, error) {
	host = normalizeDNSName(host)
	zone, soaErr := r.findSOAOwner(ctx, host)
	if soaErr != nil && ctx.Err() != nil {
		return AuthoritativeZone{}, fmt.Errorf("consulta SOA autoritativa de %s: %w", host, soaErr)
	}
	// Resolvers recursivos podem seguir um CNAME e retornar o SOA da zona de destino.
	// Uma zona autoritativa para o nome proprietário original deve ser esse nome ou um
	// de seus ancestrais DNS; aceitar um SOA não relacionado ultrapassa o escopo.
	if zone != "" && !isDNSAncestorOrSelf(host, zone) {
		zone = ""
	}
	var discoveredDelegation []string
	var discoveredParentNS []string
	var discoveredGlue map[string][]string
	var parentVerified bool
	if zone == "" {
		labels := strings.Split(host, ".")
		for i := 0; i < len(labels); i++ {
			candidate := strings.Join(labels[i:], ".")
			parent := parentZone(candidate)
			if parent != "" {
				parentNS := r.lookupExactNS(ctx, parent)
				delegated, glue, verified := r.lookupDelegationAtParent(ctx, candidate, parentNS)
				if verified {
					zone = candidate
					discoveredDelegation, discoveredParentNS = delegated, parentNS
					discoveredGlue, parentVerified = glue, true
					break
				}
			}
			if ns := r.lookupExactNS(ctx, candidate); len(ns) > 0 {
				zone = candidate
				break
			}
		}
	}
	if zone == "" {
		if soaErr != nil {
			return AuthoritativeZone{}, fmt.Errorf("zona autoritativa não encontrada para %s após resposta SOA inconclusiva: %w", host, soaErr)
		}
		return AuthoritativeZone{}, fmt.Errorf("zona autoritativa não encontrada para %s", host)
	}

	return r.authoritativeZoneDetails(
		ctx,
		zone,
		discoveredDelegation,
		discoveredParentNS,
		discoveredGlue,
		parentVerified,
	)
}

func (r *Resolver) authoritativeZoneDetails(
	ctx context.Context,
	zone string,
	discoveredDelegation []string,
	discoveredParentNS []string,
	discoveredGlue map[string][]string,
	parentVerified bool,
) (AuthoritativeZone, error) {
	zone = normalizeDNSName(zone)
	if cached, ok := r.zoneCache.Load(zone); ok {
		return cloneAuthoritativeZone(cached.(AuthoritativeZone)), nil
	}

	value, err, _ := r.zoneGroup.Do(zone, func() (interface{}, error) {
		if cached, ok := r.zoneCache.Load(zone); ok {
			return cloneAuthoritativeZone(cached.(AuthoritativeZone)), nil
		}
		result := r.buildAuthoritativeZoneDetails(
			ctx,
			zone,
			discoveredDelegation,
			discoveredParentNS,
			discoveredGlue,
			parentVerified,
		)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		r.zoneCache.Store(zone, cloneAuthoritativeZone(result))
		return result, nil
	})
	if err != nil {
		return AuthoritativeZone{}, err
	}
	return cloneAuthoritativeZone(value.(AuthoritativeZone)), nil
}

func (r *Resolver) buildAuthoritativeZoneDetails(
	ctx context.Context,
	zone string,
	discoveredDelegation []string,
	discoveredParentNS []string,
	discoveredGlue map[string][]string,
	parentVerified bool,
) AuthoritativeZone {
	result := AuthoritativeZone{
		Zone:        zone,
		ParentZone:  parentZone(zone),
		Nameservers: r.lookupExactNS(ctx, zone),
		Glue:        make(map[string][]string),
	}
	if parentVerified {
		result.Nameservers = discoveredDelegation
		result.ParentNameservers = discoveredParentNS
		result.Glue = discoveredGlue
		result.ParentDelegationVerified = true
	}
	if result.ParentZone != "" {
		if len(result.ParentNameservers) == 0 {
			result.ParentNameservers = r.lookupExactNS(ctx, result.ParentZone)
		}
		if !result.ParentDelegationVerified {
			delegated, glue, verified := r.lookupDelegationAtParent(ctx, zone, result.ParentNameservers)
			if len(delegated) > 0 {
				result.Nameservers = delegated
			}
			result.Glue = glue
			result.ParentDelegationVerified = verified
		}
		result.ParentHasDS, result.ParentDSChecked = r.lookupDSAtParent(ctx, zone, result.ParentNameservers)
		if !result.ParentDSChecked {
			status, statusErr := r.ResolveStatus(ctx, zone, mdns.TypeDS)
			if statusErr == nil && (status == core.DNSStatusResolved || status == core.DNSStatusNoData) {
				result.ParentDSChecked = true
				result.ParentHasDS = status == core.DNSStatusResolved
			}
		}
	}
	result.Nameservers = uniqueSorted(result.Nameservers)
	result.ParentNameservers = uniqueSorted(result.ParentNameservers)
	return result
}

func cloneAuthoritativeZone(value AuthoritativeZone) AuthoritativeZone {
	clone := value
	clone.Nameservers = append([]string(nil), value.Nameservers...)
	clone.ParentNameservers = append([]string(nil), value.ParentNameservers...)
	clone.Glue = make(map[string][]string, len(value.Glue))
	for nameserver, addresses := range value.Glue {
		clone.Glue[nameserver] = append([]string(nil), addresses...)
	}
	return clone
}

func (r *Resolver) lookupDSAtParent(ctx context.Context, zone string, parentNS []string) (bool, bool) {
	var servers []string
	for _, nsHost := range parentNS {
		ips, _ := r.ResolveA(ctx, nsHost)
		ips6, _ := r.ResolveAAAA(ctx, nsHost)
		servers = append(servers, ips...)
		servers = append(servers, ips6...)
	}
	client := &mdns.Client{Net: "udp", Timeout: r.operationTimeout()}
	wanted := mdns.Fqdn(zone)
	responses, complete := r.queryParentServers(ctx, servers, wanted, mdns.TypeDS,
		func(ctx context.Context, msg *mdns.Msg, endpoint string) (*mdns.Msg, error) {
			resp, _, err := client.ExchangeContext(ctx, msg, endpoint)
			return resp, err
		})
	hasDS, checked := summarizeParentDSResponses(responses, wanted)
	if !complete && !hasDS {
		// Uma coleta interrompida não pode provar a ausência de DS. Um DS já
		// observado, porém, continua sendo evidência conclusiva de presença.
		return false, false
	}
	return hasDS, checked
}

// summarizeParentDSResponses combina todas as visões válidas da zona pai. A
// presença de um único DS prevalece sobre respostas NODATA de outros servidores;
// a ausência só é considerada verificada quando ao menos uma resposta NOERROR
// válida foi observada.
func summarizeParentDSResponses(responses []*mdns.Msg, wanted string) (bool, bool) {
	checked := false
	for _, resp := range responses {
		if resp == nil || resp.Rcode != mdns.RcodeSuccess {
			continue
		}
		checked = true
		for _, section := range [][]mdns.RR{resp.Answer, resp.Ns} {
			for _, record := range section {
				if ds, ok := record.(*mdns.DS); ok && strings.EqualFold(ds.Hdr.Name, wanted) {
					return true, true
				}
			}
		}
	}
	return false, checked
}

func (r *Resolver) findSOAOwner(ctx context.Context, host string) (string, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(host), mdns.TypeSOA)
	msg.RecursionDesired = true
	resp, err := r.exchange(ctx, msg)
	if err != nil {
		return "", err
	}
	if resp == nil {
		return "", fmt.Errorf("resposta DNS vazia")
	}
	for _, section := range [][]mdns.RR{resp.Answer, resp.Ns} {
		for _, rr := range section {
			if soa, ok := rr.(*mdns.SOA); ok {
				return normalizeDNSName(soa.Hdr.Name), nil
			}
		}
	}
	switch resp.Rcode {
	case mdns.RcodeSuccess, mdns.RcodeNameError:
		return "", nil
	case mdns.RcodeServerFailure, mdns.RcodeRefused:
		return "", fmt.Errorf("rcode DNS inconclusivo %s", mdns.RcodeToString[resp.Rcode])
	default:
		return "", fmt.Errorf("rcode DNS inesperado %s", mdns.RcodeToString[resp.Rcode])
	}
}

func (r *Resolver) lookupExactNS(ctx context.Context, name string) []string {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(name), mdns.TypeNS)
	msg.RecursionDesired = true
	resp, err := r.exchange(ctx, msg)
	if err != nil || resp == nil {
		return nil
	}
	wanted := mdns.Fqdn(name)
	var out []string
	for _, rr := range append(append([]mdns.RR{}, resp.Answer...), resp.Ns...) {
		if ns, ok := rr.(*mdns.NS); ok && strings.EqualFold(ns.Hdr.Name, wanted) {
			out = append(out, normalizeDNSName(ns.Ns))
		}
	}
	return uniqueSorted(out)
}

func (r *Resolver) lookupDelegationAtParent(ctx context.Context, zone string, parentNS []string) ([]string, map[string][]string, bool) {
	var servers []string
	for _, nsHost := range parentNS {
		ips, _ := r.ResolveA(ctx, nsHost)
		ips6, _ := r.ResolveAAAA(ctx, nsHost)
		servers = append(servers, ips...)
		servers = append(servers, ips6...)
	}
	client := &mdns.Client{Net: "udp", Timeout: r.operationTimeout()}
	wanted := mdns.Fqdn(zone)
	responses, complete := r.queryParentServers(ctx, servers, wanted, mdns.TypeNS,
		func(ctx context.Context, msg *mdns.Msg, endpoint string) (*mdns.Msg, error) {
			resp, _, err := client.ExchangeContext(ctx, msg, endpoint)
			return resp, err
		})
	delegated, glue, verified := summarizeParentDelegationResponses(responses, wanted)
	if !complete {
		return delegated, glue, false
	}
	return delegated, glue, verified
}

type parentDNSExchange func(context.Context, *mdns.Msg, string) (*mdns.Msg, error)

// queryParentServers consulta todos os endereços conhecidos dos servidores da
// zona pai. Erros individuais de rede não interrompem a coleta; apenas uma falha
// do limitador ou o cancelamento do contexto torna a passagem incompleta.
func (r *Resolver) queryParentServers(
	ctx context.Context,
	servers []string,
	wanted string,
	qtype uint16,
	exchange parentDNSExchange,
) ([]*mdns.Msg, bool) {
	servers = uniqueSorted(servers)
	responses := make([]*mdns.Msg, 0, len(servers))
	for _, server := range servers {
		if ctx.Err() != nil {
			return responses, false
		}
		msg := new(mdns.Msg)
		msg.SetQuestion(wanted, qtype)
		msg.RecursionDesired = false
		if err := r.wait(ctx); err != nil {
			return responses, false
		}
		resp, err := exchange(ctx, msg, net.JoinHostPort(server, "53"))
		if err == nil && resp != nil {
			responses = append(responses, resp)
		}
	}
	return responses, ctx.Err() == nil
}

// summarizeParentDelegationResponses exige consenso entre todas as visões
// válidas e responsivas da zona pai. Falhas de transporte e SERVFAIL permanecem
// inconclusivas, mas conjuntos NS distintos — inclusive uma resposta negativa
// válida em conflito com uma delegação — impedem a confirmação.
func summarizeParentDelegationResponses(responses []*mdns.Msg, wanted string) ([]string, map[string][]string, bool) {
	var reference []string
	var combined []string
	glue := make(map[string][]string)
	validViews := 0
	consistent := true

	for _, resp := range responses {
		if resp == nil || (resp.Rcode != mdns.RcodeSuccess && resp.Rcode != mdns.RcodeNameError) {
			continue
		}
		delegated := delegationNameservers(resp, wanted)
		if validViews == 0 {
			reference = delegated
		} else if !equalDNSNameSets(reference, delegated) {
			consistent = false
		}
		validViews++
		combined = append(combined, delegated...)
		mergeDelegationGlue(glue, resp.Extra, delegated)
	}

	combined = uniqueSorted(combined)
	for nameserver, addresses := range glue {
		glue[nameserver] = uniqueSorted(addresses)
	}
	verified := validViews > 0 && consistent && len(reference) > 0
	return combined, glue, verified
}

func delegationNameservers(resp *mdns.Msg, wanted string) []string {
	var delegated []string
	for _, rr := range append(append([]mdns.RR{}, resp.Answer...), resp.Ns...) {
		if ns, ok := rr.(*mdns.NS); ok && strings.EqualFold(ns.Hdr.Name, wanted) {
			delegated = append(delegated, normalizeDNSName(ns.Ns))
		}
	}
	return uniqueSorted(delegated)
}

func mergeDelegationGlue(destination map[string][]string, records []mdns.RR, delegated []string) {
	allowed := make(map[string]struct{}, len(delegated))
	for _, nameserver := range delegated {
		allowed[normalizeDNSName(nameserver)] = struct{}{}
	}
	for _, rr := range records {
		owner := normalizeDNSName(rr.Header().Name)
		if _, ok := allowed[owner]; !ok {
			continue
		}
		switch value := rr.(type) {
		case *mdns.A:
			destination[owner] = append(destination[owner], value.A.String())
		case *mdns.AAAA:
			destination[owner] = append(destination[owner], value.AAAA.String())
		}
	}
}

func equalDNSNameSets(left, right []string) bool {
	left = uniqueSorted(left)
	right = uniqueSorted(right)
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func parentZone(zone string) string {
	parts := strings.Split(normalizeDNSName(zone), ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[1:], ".")
}

func normalizeDNSName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func isDNSAncestorOrSelf(name, candidateZone string) bool {
	name = normalizeDNSName(name)
	candidateZone = normalizeDNSName(candidateZone)
	return name != "" && candidateZone != "" &&
		(name == candidateZone || strings.HasSuffix(name, "."+candidateZone))
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizeDNSName(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
