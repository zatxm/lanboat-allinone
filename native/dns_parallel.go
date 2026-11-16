package native

import (
	"context"
	"errors"
	"sync"
)

// Each evaluation is immutable after done closes; only the coordinator owns rule state.
type dnsEvaluation struct {
	done  chan struct{}
	reply []byte
	err   error
}
type dnsRuleResult struct {
	matched  bool
	rule     *DNSRule
	options  DNSRule
	selected []byte
	err      error
}
type dnsCoordinator struct {
	resolver *resolver
	ctx      context.Context
	query    []byte
	real     bool
	races    chan dnsRuleResult
	pending  int
	winner   *dnsRuleResult
	workers  sync.WaitGroup
	slots    chan struct{}
}

func ruleHasResponse(o Rule) bool {
	if o.MatchResponse != "" {
		return true
	}
	for _, child := range o.Rules {
		if ruleHasResponse(child) {
			return true
		}
	}
	return false
}
func (c *dnsCoordinator) start(server string, o DNSRule) *dnsEvaluation {
	f := &dnsEvaluation{done: make(chan struct{})}
	c.workers.Add(1)
	go func() {
		defer c.workers.Done()
		defer close(f.done)
		select {
		case c.slots <- struct{}{}:
			defer func() { <-c.slots }()
		case <-c.ctx.Done():
			f.err = c.ctx.Err()
			return
		}
		f.reply, f.err = c.resolver.exchangeDNSOn(c.ctx, server, c.query, o, c.real)
	}()
	return f
}
func (c *dnsCoordinator) accept(result dnsRuleResult) {
	c.pending--
	if result.matched && c.winner == nil {
		c.winner = &result
	}
}
func (c *dnsCoordinator) wait(f *dnsEvaluation) error {
	for {
		if c.winner != nil {
			return errDNSRaceWon
		}
		select {
		case result := <-c.races:
			c.accept(result)
		case <-f.done:
			return f.err
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
	}
}
func (c *dnsCoordinator) settle() error {
	for c.pending > 0 && c.winner == nil {
		select {
		case result := <-c.races:
			c.accept(result)
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
	}
	if c.winner != nil {
		return errDNSRaceWon
	}
	return nil
}
func (c *dnsCoordinator) poll() {
	for c.pending > 0 && c.winner == nil {
		select {
		case result := <-c.races:
			c.accept(result)
		default:
			return
		}
	}
}

var errDNSRaceWon = errors.New("DNS race rule matched")

func dnsResponseState(ctx context.Context, o Rule, evaluations map[string]*dnsEvaluation, wait func(*dnsEvaluation) error) (dnsPolicyState, error) {
	state := dnsPolicyState{responses: map[string][]byte{}}
	var collect func(Rule) error
	collect = func(rule Rule) error {
		if rule.MatchResponse != "" {
			key := string(rule.MatchResponse)
			if f := evaluations[key]; f != nil {
				e := wait(f)
				if errors.Is(e, errDNSRaceWon) {
					return e
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				// An upstream transport failure is an unavailable response, not a match.
				if e == nil {
					state.responses[key] = f.reply
				}
			}
		}
		for _, child := range rule.Rules {
			if e := collect(child); e != nil {
				return e
			}
		}
		return nil
	}
	if e := collect(o); e != nil {
		return state, e
	}
	return state, nil
}
func (c *dnsCoordinator) match(policy *dnsPolicy, q request, options DNSRule, evaluations map[string]*dnsEvaluation, latest *dnsEvaluation, wait func(*dnsEvaluation) error) dnsRuleResult {
	result := dnsRuleResult{rule: &policy.options, options: options}
	if hasResponseCondition(policy.rule) {
		state, e := dnsResponseState(c.ctx, policy.options.Rule, evaluations, wait)
		result.err = e
		if e == nil {
			result.matched = policy.rule.responseMatches(q, &state)
			result.selected = state.selected
		}
	} else {
		m := policy.rule.evaluate(q)
		result.matched = m == matchYes
		if m == matchUnknown {
			tag := policy.options.Server
			if tag == "" {
				tag = c.resolver.server.Tag
			}
			f := c.start(tag, options)
			if result.err = wait(f); result.err == nil {
				ips, _, e := parseDNSReply(c.query, f.reply)
				result.err = e
				if e == nil {
					target := q
					target.ips = ips
					result.matched = policy.rule.matches(target)
					result.selected = f.reply
				}
			}
		}
	}
	if result.matched {
		mergeDNSOptions(&result.options, policy.options)
		if policy.options.Action == "respond" && result.selected == nil && latest != nil {
			result.err = wait(latest)
			result.selected = latest.reply
		}
	}
	return result
}
func (r *resolver) exchangeParallelDNS(ctx context.Context, query []byte, real bool, q request, options DNSRule, end int) ([]byte, error) {
	queryCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	c := &dnsCoordinator{resolver: r, ctx: queryCtx, query: query, real: real, races: make(chan dnsRuleResult, r.parallelRaces), slots: make(chan struct{}, 8)}
	defer func() { cancel(); stop(); c.workers.Wait() }()
	evaluations := map[string]*dnsEvaluation{}
	var latest *dnsEvaluation
	var terminal *dnsRuleResult
	var speculative *dnsEvaluation
	for i := range r.policies {
		policy := &r.policies[i]
		c.poll()
		if c.winner != nil {
			break
		}
		o := policy.options
		if real && r.servers[o.Server].Type == "fakeip" {
			continue
		}
		if o.Race {
			snapshot := make(map[string]*dnsEvaluation, len(evaluations))
			for k, v := range evaluations {
				snapshot[k] = v
			}
			c.pending++
			c.workers.Add(1)
			go func(latest *dnsEvaluation, options DNSRule) {
				defer c.workers.Done()
				wait := func(f *dnsEvaluation) error {
					select {
					case <-f.done:
						return f.err
					case <-queryCtx.Done():
						return queryCtx.Err()
					}
				}
				result := c.match(policy, q, options, snapshot, latest, wait)
				select {
				case c.races <- result:
				case <-queryCtx.Done():
				}
			}(latest, options)
			continue
		}
		result := c.match(policy, q, options, evaluations, latest, c.wait)
		if errors.Is(result.err, errDNSRaceWon) {
			break
		}
		if result.err != nil {
			return nil, result.err
		}
		if !result.matched {
			continue
		}
		if !o.Speculative {
			if e := c.settle(); errors.Is(e, errDNSRaceWon) {
				break
			} else if e != nil {
				return nil, e
			}
		}
		switch o.Action {
		case "evaluate":
			f := c.start(o.Server, result.options)
			tag := o.Tag
			if tag == "" {
				tag = "@last"
				latest = f
			}
			evaluations[tag] = f
		case "route-options":
			options = result.options
		default:
			terminal = &result
			if o.Speculative && (o.Action == "" || o.Action == "route") {
				speculative = c.start(o.Server, result.options)
			}
		}
		if terminal != nil {
			break
		}
	}
	if c.winner == nil {
		if e := c.settle(); e != nil && !errors.Is(e, errDNSRaceWon) {
			return nil, e
		}
	}
	if c.winner != nil {
		terminal = c.winner
		// Matched race rules commit before querying their chosen terminal server.
		cancel()
		c.workers.Wait()
	} else if speculative != nil {
		if e := c.wait(speculative); e != nil {
			return nil, e
		}
		return speculative.reply, nil
	}
	if terminal == nil {
		return r.exchangeDNSOn(ctx, r.server.Tag, query, options, real)
	}
	o := terminal.rule
	switch o.Action {
	case "respond":
		if terminal.selected == nil {
			return nil, errors.New("respond has no evaluated response")
		}
		return append([]byte(nil), terminal.selected...), nil
	case "predefined":
		return predefinedDNS(query, *o)
	case "reject":
		if r.reject.drop(o.Method, o.NoDrop) {
			return nil, ErrDropped
		}
		return dnsResponse(query, end, nil, 0, 5), nil
	default:
		return r.exchangeDNSOn(ctx, o.Server, query, terminal.options, real)
	}
}
