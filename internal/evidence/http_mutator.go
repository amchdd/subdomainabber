package evidence

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

type HTTPMutatorCollector struct {
	signatures         []signatures.Fingerprint
	transport          HTTPRawTransport
	mutations          []HTTPMutation
	requestLimiter     interface{ Wait(context.Context) error }
	maxProbes          int
	hostTimeout        time.Duration
	framingOnly        bool
	allowedAuthorities map[string]struct{}
}

func NewHTTPFramingCollector(timeout time.Duration, authorities []string) (*HTTPMutatorCollector, error) {
	collector := NewHTTPMutatorCollector(nil, timeout)
	collector.framingOnly = true
	collector.mutations = ExperimentalFramingMutations()
	collector.allowedAuthorities = make(map[string]struct{}, len(authorities))
	for _, authority := range authorities {
		normalized := strings.ToLower(strings.TrimSpace(authority))
		if normalized != "" {
			collector.allowedAuthorities[normalized] = struct{}{}
		}
	}
	if len(collector.allowedAuthorities) == 0 {
		return nil, fmt.Errorf("o framing exige uma lista permitida explícita de autoridades não vazia")
	}
	return collector, nil
}

func NewHTTPMutatorCollector(sigs []signatures.Fingerprint, timeout time.Duration) *HTTPMutatorCollector {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPMutatorCollector{
		signatures:  append([]signatures.Fingerprint(nil), sigs...),
		transport:   NewNetworkHTTPRawTransport(timeout),
		mutations:   DefaultHTTPMutations(),
		maxProbes:   7,
		hostTimeout: 4 * timeout,
	}
}

func (collector *HTTPMutatorCollector) SetRequestLimiter(limiter interface{ Wait(context.Context) error }) {
	collector.requestLimiter = limiter
}

func (collector *HTTPMutatorCollector) SetLimits(maxProbes int, hostTimeout time.Duration) {
	if maxProbes > 0 {
		collector.maxProbes = maxProbes
	}
	if hostTimeout > 0 {
		collector.hostTimeout = hostTimeout
	}
}

func (collector *HTTPMutatorCollector) Name() string {
	if collector.framingOnly {
		return "HTTP_FRAMING_LAB"
	}
	return "HTTP_MUTATOR"
}

func (collector *HTTPMutatorCollector) Phase() CollectorPhase {
	return PhaseHTTPMutation
}

func (collector *HTTPMutatorCollector) SetTransport(transport HTTPRawTransport) {
	if transport != nil {
		collector.transport = transport
	}
}

func (collector *HTTPMutatorCollector) ConfigureProxy(rawProxy string) error {
	transport, ok := collector.transport.(*NetworkHTTPRawTransport)
	if !ok && rawProxy != "" {
		return fmt.Errorf("o transporte raw configurado não oferece suporte a proxy")
	}
	if !ok {
		return nil
	}
	return transport.SetProxy(rawProxy)
}

func (collector *HTTPMutatorCollector) SetMutations(mutations []HTTPMutation) {
	collector.mutations = append([]HTTPMutation(nil), mutations...)
}

func (collector *HTTPMutatorCollector) Collect(ctx context.Context, analysis *core.HostAnalysis) error {
	analysis.AddTestedVector(collector.Name())
	candidates := analysis.ProviderCandidateSnapshot()
	if !collector.framingOnly {
		candidates = collector.mutationCandidates(candidates)
	}
	if (!collector.framingOnly && len(candidates) == 0) || collector.transport == nil || len(collector.mutations) == 0 {
		return nil
	}
	if collector.framingOnly {
		if _, allowed := collector.allowedAuthorities[strings.ToLower(strings.TrimSpace(analysis.Host))]; !allowed {
			return nil
		}
	}

	budget := newMutationNetworkBudget(collector.hostTimeout)
schemeLoop:
	for _, scheme := range []string{"https", "http"} {
		probeCount := 0
		baseline, exists := analysis.HTTPObservation(scheme)
		if !exists || !baseline.Complete {
			continue
		}
		blockDecision := decideBlock(scheme, baseline)
		if !collector.framingOnly && !blockDecision.Blocked && opaqueProviderEdgeStatus(baseline.StatusCode) &&
			!collector.bodyMatchesCandidate(core.MutationContext{ProviderCandidates: candidates}, baseline.Body) {
			blockDecision.Blocked = true
			blockDecision.Confidence = 35
			blockDecision.Reasons = append(blockDecision.Reasons, fmt.Sprintf(
				"status opaco %d da camada intermediária vinculada ao provedor selecionado para revisão explícita por mutação",
				baseline.StatusCode,
			))
		}
		mutationContext, targetErr := mutationContextForAuthority(analysis.Host, scheme)
		if targetErr != nil {
			return targetErr
		}
		mutationContext.Baseline = baseline
		mutationContext.ProviderCandidates = append([]core.ProviderCandidate(nil), candidates...)
		mutationContext.BlockDecision = blockDecision
		if !blockDecision.Blocked {
			continue
		}

		for _, mutation := range collector.mutations {
			if budget.Exhausted() {
				break schemeLoop
			}
			if isFramingMutation(mutation) != collector.framingOnly {
				continue
			}
			if collector.maxProbes > 0 && probeCount >= collector.maxProbes {
				break
			}
			if !mutation.Applicability(mutationContext) {
				continue
			}
			probeCount++
			collector.executeMutation(ctx, analysis, mutationContext, mutation, budget)
		}
	}
	return nil
}

func (collector *HTTPMutatorCollector) mutationCandidates(candidates []core.ProviderCandidate) []core.ProviderCandidate {
	result := make([]core.ProviderCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		vector := strings.ToUpper(strings.TrimSpace(candidate.Vector))
		if candidate.CNAME == "" || (vector != "" && vector != "CNAME") {
			continue
		}
		for index := range collector.signatures {
			signature := &collector.signatures[index]
			if signature.Fingerprint != "" && candidateMatchesSignature(candidate, signature) {
				result = append(result, candidate)
				break
			}
		}
	}
	return result
}

func opaqueProviderEdgeStatus(status int) bool {
	return status == 404 || status == 503
}

func mutationContextForAuthority(authority, scheme string) (core.MutationContext, error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return core.MutationContext{}, fmt.Errorf("autoridade de mutação vazia")
	}
	dialHost := authority
	port := 80
	if strings.EqualFold(scheme, "https") {
		port = 443
	}
	if splitHost, splitPort, err := net.SplitHostPort(authority); err == nil {
		parsedPort, parseErr := strconv.Atoi(splitPort)
		if parseErr != nil {
			return core.MutationContext{}, fmt.Errorf("porta da autoridade inválida: %w", parseErr)
		}
		dialHost, port = splitHost, parsedPort
	}
	if dialHost == "" || port < 1 || port > 65535 {
		return core.MutationContext{}, fmt.Errorf("destino de mutação inválido %q", authority)
	}
	return core.MutationContext{DialHost: dialHost, DialPort: port, HTTPAuthority: authority, TLSServerName: dialHost, Scheme: scheme}, nil
}

func isFramingMutation(mutation HTTPMutation) bool {
	return mutation.Name() == "CLTEProbe" || mutation.Name() == "TECLProbe"
}

func (collector *HTTPMutatorCollector) executeMutation(ctx context.Context, analysis *core.HostAnalysis, mutationContext core.MutationContext, mutation HTTPMutation, budget *mutationNetworkBudget) {
	framing := isFramingMutation(mutation)
	controlPayload, err := mutation.BuildControl(mutationContext)
	var mutationPayload []byte
	if err == nil {
		mutationPayload, err = mutation.BuildMutation(mutationContext)
	}
	if err != nil {
		outcome := core.MutationRejected
		if framing {
			outcome = core.MutationFramingRejected
		}
		analysis.AddMutationResult(core.MutationResult{
			Name:         mutation.Name(),
			BaselineID:   mutationContext.BlockDecision.BaselineID,
			StatusBefore: mutationContext.Baseline.StatusCode,
			Error:        err.Error(),
			Outcome:      outcome,
		})
		return
	}

	observations := core.ExperimentObservations{}
	observations.ControlBefore = collector.send(ctx, mutationContext, controlPayload, budget)
	observations.MutationFirst = collector.send(ctx, mutationContext, mutationPayload, budget)
	observations.MutationSecond = collector.send(ctx, mutationContext, mutationPayload, budget)
	observations.ControlAfter = collector.send(ctx, mutationContext, controlPayload, budget)
	aggregate := core.MutationResult{Name: mutation.Name(), BaselineID: mutationContext.BlockDecision.BaselineID,
		Attempts: 2, StatusBefore: observations.ControlBefore.StatusCode, StatusAfter: observations.MutationFirst.StatusCode,
		Observation: observations.MutationFirst, Experiment: observations}
	for _, observed := range []core.RawHTTPObservation{observations.ControlBefore, observations.MutationFirst, observations.MutationSecond, observations.ControlAfter} {
		if !usableRawObservation(observed) {
			aggregate.Outcome = core.MutationTransportFailure
			if framing {
				aggregate.Outcome = core.MutationFramingTransportFailure
			}
			aggregate.Error = firstNonEmpty(observed.TransportError, observed.ParseError, "resposta incompleta")
			analysis.AddMutationResult(aggregate)
			return
		}
	}
	if observations.ControlBefore.StatusCode == 400 || observations.MutationFirst.StatusCode == 400 || observations.MutationSecond.StatusCode == 400 || observations.ControlAfter.StatusCode == 400 {
		aggregate.Outcome = core.MutationRejected
		if framing {
			aggregate.Outcome = core.MutationFramingRejected
		}
		aggregate.Error = "o servidor rejeitou a requisição mutada com HTTP 400"
		analysis.AddMutationResult(aggregate)
		return
	}
	controlsStable := mutationResponsesEquivalent(observations.ControlBefore, observations.ControlAfter)
	mutationsStable := mutationResponsesEquivalent(observations.MutationFirst, observations.MutationSecond)
	different := !mutationResponsesEquivalent(observations.ControlBefore, observations.MutationFirst)
	if !controlsStable || !mutationsStable {
		aggregate.Outcome = core.MutationNoDifference
		if framing {
			aggregate.Outcome = core.MutationFramingNoDifference
		}
		aggregate.Error = "a resposta de controle ou da mutação não foi reproduzível"
		analysis.AddMutationResult(aggregate)
		return
	}
	if !different {
		aggregate.Outcome = core.MutationNoDifference
		if framing {
			aggregate.Outcome = core.MutationFramingNoDifference
		}
		analysis.AddMutationResult(aggregate)
		return
	}
	aggregate.Confirmations = 2
	aggregate.Outcome = core.MutationReproducibleDifferential
	if framing {
		aggregate.Outcome = core.MutationFramingDifferential
	}
	if observations.ControlBefore.StatusCode != observations.MutationFirst.StatusCode {
		aggregate.RelevantDiffs = append(aggregate.RelevantDiffs, core.Difference{Field: "status", Before: strconv.Itoa(observations.ControlBefore.StatusCode), After: strconv.Itoa(observations.MutationFirst.StatusCode)})
	}
	controlHash := hashBytes(normalizeHTTPBody(observations.ControlBefore.Body))
	mutationHash := hashBytes(normalizeHTTPBody(observations.MutationFirst.Body))
	if controlHash != mutationHash {
		aggregate.RelevantDiffs = append(aggregate.RelevantDiffs, core.Difference{Field: "body_hash", Before: controlHash, After: mutationHash})
	}
	if framing {
		analysis.AddEvidence(core.Evidence{Type: "FRAMING_DIFFERENTIAL", Source: mutation.Name(), Description: "Diferença de framing reproduzível observada em ambiente explicitamente autorizado; não é evidência de provedor nem de takeover.", Weight: 0, Confidence: 70, Metadata: map[string]string{"baseline_id": mutationContext.BlockDecision.BaselineID, "attempts": "2", "confirmations": "2"}})
		analysis.AddMutationResult(aggregate)
		return
	}
	controlHasProviderFingerprint := collector.observationMatchesCandidate(mutationContext, observations.ControlBefore) ||
		collector.observationMatchesCandidate(mutationContext, observations.ControlAfter)
	baselineHasProviderFingerprint := collector.bodyMatchesCandidate(mutationContext, mutationContext.Baseline.Body)
	if controlHasProviderFingerprint && !baselineHasProviderFingerprint {
		analysis.AddEvidence(core.Evidence{
			Type: "HTTP_RAW_CONTROL_DIFFERENTIAL", Source: mutation.Name(),
			Description: "O controle bruto (raw) equivalente já revelou a assinatura; nenhuma diferença foi atribuída à mutação.",
			Weight:      0, Confidence: 60,
			Metadata: map[string]string{"baseline_id": mutationContext.BlockDecision.BaselineID, "attempts": "2", "confirmations": "2"},
		})
	}
	evidenceType := differentialEvidenceType()
	if !controlHasProviderFingerprint {
		analysis.AddEvidence(core.Evidence{
			Type:        evidenceType,
			Source:      mutation.Name(),
			Description: "A mutação HTTP produziu uma resposta diferencial reproduzível; isso não confirma takeover nem request smuggling.",
			Weight:      0,
			Confidence:  70,
			Metadata: map[string]string{
				"baseline_id":   mutationContext.BlockDecision.BaselineID,
				"attempts":      "2",
				"confirmations": "2",
			},
		})
	}

	if !controlHasProviderFingerprint && !baselineHasProviderFingerprint {
		if revealed, ok := collector.confirmedProviderFingerprint(mutationContext, mutation.Name(), observations.MutationFirst, observations.MutationSecond, observations.ControlBefore, observations.ControlAfter); ok {
			aggregate.Outcome = core.MutationRevealedProviderFingerprint
			analysis.AddEvidence(revealedFingerprintEvidence(revealed))
		} else if review, reviewOK := collector.genericFingerprintReview(mutationContext, mutation.Name(), observations); reviewOK {
			analysis.AddEvidence(review)
		}
	}
	analysis.AddMutationResult(aggregate)
}

func (collector *HTTPMutatorCollector) send(ctx context.Context, mutationContext core.MutationContext, payload []byte, budget *mutationNetworkBudget) core.RawHTTPObservation {
	if budget.Exhausted() {
		return core.RawHTTPObservation{TransportError: "o orçamento de rede das mutações foi esgotado"}
	}
	if collector.requestLimiter != nil {
		if err := collector.requestLimiter.Wait(ctx); err != nil {
			return core.RawHTTPObservation{TransportError: err.Error()}
		}
	}
	if err := ctx.Err(); err != nil {
		return core.RawHTTPObservation{TransportError: err.Error()}
	}
	networkContext, cancel := budget.Context(ctx)
	started := time.Now()
	observation := collector.transport.Send(networkContext, mutationContext, payload)
	budget.Consume(time.Since(started))
	cancel()
	return observation
}

type mutationNetworkBudget struct {
	remaining time.Duration
	enabled   bool
}

func newMutationNetworkBudget(limit time.Duration) *mutationNetworkBudget {
	return &mutationNetworkBudget{remaining: limit, enabled: limit > 0}
}

func (budget *mutationNetworkBudget) Context(parent context.Context) (context.Context, context.CancelFunc) {
	if budget == nil || !budget.enabled {
		return context.WithCancel(parent)
	}
	if budget.remaining <= 0 {
		contextValue, cancel := context.WithCancel(parent)
		cancel()
		return contextValue, func() {}
	}
	return context.WithTimeout(parent, budget.remaining)
}

func (budget *mutationNetworkBudget) Consume(duration time.Duration) {
	if budget == nil || !budget.enabled {
		return
	}
	budget.remaining -= duration
	if budget.remaining < 0 {
		budget.remaining = 0
	}
}

func (budget *mutationNetworkBudget) Exhausted() bool {
	return budget != nil && budget.enabled && budget.remaining <= 0
}

func (collector *HTTPMutatorCollector) confirmedProviderFingerprint(mutationContext core.MutationContext, mutationName string, firstRaw, secondRaw, firstControlRaw, secondControlRaw core.RawHTTPObservation) (core.RevealedProviderFingerprint, bool) {
	if !usableRawObservation(firstRaw) || !usableRawObservation(secondRaw) || !usableRawObservation(firstControlRaw) || !usableRawObservation(secondControlRaw) {
		return core.RevealedProviderFingerprint{}, false
	}
	if firstRaw.StatusCode == 400 || secondRaw.StatusCode == 400 {
		return core.RevealedProviderFingerprint{}, false
	}

	for _, candidate := range mutationContext.ProviderCandidates {
		for index := range collector.signatures {
			signature := &collector.signatures[index]
			if signature.Service != candidate.Service || signature.Fingerprint == "" || strings.EqualFold(signature.Fingerprint, "NXDOMAIN") {
				continue
			}
			if !candidateMatchesSignature(candidate, signature) {
				continue
			}
			if signatures.MatchesFingerprint(string(mutationContext.Baseline.Body), signature) {
				continue
			}
			if signatures.MatchesFingerprint(string(firstControlRaw.Body), signature) || signatures.MatchesFingerprint(string(secondControlRaw.Body), signature) {
				continue
			}
			if !signatures.MatchesFingerprint(string(firstRaw.Body), signature) || !signatures.MatchesFingerprint(string(secondRaw.Body), signature) {
				continue
			}
			rule, firstEligible := eligibleTakeoverFingerprint(signature, candidate, firstRaw)
			_, secondEligible := eligibleTakeoverFingerprint(signature, candidate, secondRaw)
			if !firstEligible || !secondEligible {
				continue
			}
			mutatedHash := hashBytes(normalizeHTTPBody(firstRaw.Body))
			return core.RevealedProviderFingerprint{
				RuleID:             rule.RuleID,
				ProviderID:         candidate.ProviderID,
				Service:            candidate.Service,
				CNAME:              candidate.CNAME,
				Mutation:           mutationName,
				BaselineStatus:     firstControlRaw.StatusCode,
				MutatedStatus:      firstRaw.StatusCode,
				BaselineBodyHash:   hashBytes(normalizeHTTPBody(firstControlRaw.Body)),
				MutatedBodyHash:    mutatedHash,
				MatchedFingerprint: signature.Fingerprint,
				Specificity:        fingerprintSpecificity(signature.Fingerprint),
				Attempts:           2,
				Confirmations:      2,
			}, true
		}
	}
	return core.RevealedProviderFingerprint{}, false
}

func (collector *HTTPMutatorCollector) genericFingerprintReview(ctx core.MutationContext, mutationName string, observations core.ExperimentObservations) (core.Evidence, bool) {
	for _, candidate := range ctx.ProviderCandidates {
		for index := range collector.signatures {
			signature := &collector.signatures[index]
			if signature.Service != candidate.Service || !candidateMatchesSignature(candidate, signature) {
				continue
			}
			if signatures.MatchesFingerprint(string(ctx.Baseline.Body), signature) || signatures.MatchesFingerprint(string(observations.ControlBefore.Body), signature) || signatures.MatchesFingerprint(string(observations.ControlAfter.Body), signature) {
				continue
			}
			if !signatures.MatchesFingerprint(string(observations.MutationFirst.Body), signature) || !signatures.MatchesFingerprint(string(observations.MutationSecond.Body), signature) {
				continue
			}
			rule, eligible := eligibleTakeoverFingerprint(signature, candidate, observations.MutationFirst)
			if eligible {
				continue
			}
			return core.Evidence{Type: "HTTP_MUTATION_FINGERPRINT_REVIEW", Source: candidate.Service, Description: "Assinatura reproduzível, porém inelegível para classificação automática; requer revisão manual.", Weight: 0, Confidence: 40, Metadata: map[string]string{"rule_id": rule.RuleID, "provider_id": candidate.ProviderID, "cname": candidate.CNAME, "mutation": mutationName, "matched_fingerprint": signature.Fingerprint, "claimability": rule.Claimability}}, true
		}
	}
	return core.Evidence{}, false
}

func (collector *HTTPMutatorCollector) observationMatchesCandidate(ctx core.MutationContext, observation core.RawHTTPObservation) bool {
	return collector.bodyMatchesCandidate(ctx, observation.Body)
}

func (collector *HTTPMutatorCollector) bodyMatchesCandidate(ctx core.MutationContext, body []byte) bool {
	for _, candidate := range ctx.ProviderCandidates {
		for index := range collector.signatures {
			signature := &collector.signatures[index]
			if signature.Service == candidate.Service && signature.Fingerprint != "" && candidateMatchesSignature(candidate, signature) && signatures.MatchesFingerprint(string(body), signature) {
				return true
			}
		}
	}
	return false
}

func candidateMatchesSignature(candidate core.ProviderCandidate, signature *signatures.Fingerprint) bool {
	if candidate.CNAME == "" || len(signature.CNames) == 0 {
		return false
	}
	for _, pattern := range signature.CNames {
		if domainutil.MatchDNSName(candidate.CNAME, pattern) {
			return true
		}
	}
	return false
}

func mutationResponsesEquivalent(first, second core.RawHTTPObservation) bool {
	return usableRawObservation(first) && usableRawObservation(second) && first.StatusCode == second.StatusCode && bytes.Equal(normalizeHTTPBody(first.Body), normalizeHTTPBody(second.Body))
}

func usableRawObservation(observation core.RawHTTPObservation) bool {
	return observation.Complete && !observation.TimedOut && !observation.ConnectionReset && observation.TransportError == "" && observation.ParseError == ""
}

func revealedFingerprintEvidence(revealed core.RevealedProviderFingerprint) core.Evidence {
	return core.Evidence{
		Type:        "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT",
		Source:      revealed.Service,
		Description: fmt.Sprintf("A mutação %s revelou, de forma reproduzível, uma assinatura específica de %s", revealed.Mutation, revealed.Service),
		Weight:      50,
		Confidence:  90,
		Metadata: map[string]string{
			"rule_id":             revealed.RuleID,
			"provider_id":         revealed.ProviderID,
			"cname":               revealed.CNAME,
			"mutation":            revealed.Mutation,
			"baseline_status":     strconv.Itoa(revealed.BaselineStatus),
			"mutated_status":      strconv.Itoa(revealed.MutatedStatus),
			"baseline_body_hash":  revealed.BaselineBodyHash,
			"mutated_body_hash":   revealed.MutatedBodyHash,
			"matched_fingerprint": revealed.MatchedFingerprint,
			"specificity":         strconv.Itoa(revealed.Specificity),
			"attempts":            strconv.Itoa(revealed.Attempts),
			"confirmations":       strconv.Itoa(revealed.Confirmations),
		},
	}
}
