package native

// Cache required metadata when compiling rule sets; pre-match never walks a
// large domain/IP snapshot just to discover that its domain is still unknown.
func preMatchFields(o Rule) uint32 {
	var fields uint32
	for i, needed := range [...]bool{len(o.Domain)+len(o.DomainSuffix)+len(o.DomainKeyword)+len(o.DomainRegex) > 0 || o.domains != nil, len(o.Protocol) > 0, len(o.AuthUser) > 0, len(o.ProcessName) > 0, len(o.ProcessPath)+len(o.ProcessPathRegex) > 0, len(o.PackageName)+len(o.PackageNameRegex) > 0, len(o.NetworkType) > 0, len(o.WiFiSSID) > 0, len(o.WiFiBSSID) > 0, o.NetworkIsExpensive || o.NetworkIsConstrained, len(o.Client) > 0, len(o.NetworkInterfaceAddress) > 0, len(o.DefaultInterfaceAddress) > 0, len(o.User) > 0, len(o.UserID) > 0, len(o.SourceMACAddress) > 0, len(o.SourceHostname) > 0} {
		if needed {
			fields |= 1 << i
		}
	}
	return fields
}
func preMatchMissing(m Metadata) uint32 {
	var missing uint32
	for i, unknown := range [...]bool{m.Domain == "", m.Protocol == "", m.AuthUser == "", m.ProcessName == "", m.ProcessPath == "", m.PackageName == "", m.NetworkType == "", m.WiFiSSID == "", m.WiFiBSSID == "", true, m.Client == "", m.NetworkInterfaceAddress == nil, m.DefaultInterfaceAddress == nil, m.User == "", m.UserID == nil, m.SourceMACAddress == "", m.SourceHostname == ""} {
		if unknown {
			missing |= 1 << i
		}
	}
	return missing
}
func (r *routeRule) preMatchNeedsData(q request) bool {
	return r.missingPreMatchFields(preMatchMissing(q.metadata))
}
func (r *routeRule) missingPreMatchFields(missing uint32) bool {
	if r.preMatchFields&missing != 0 {
		return true
	}
	for _, set := range r.sets {
		if snapshot := set.current.Load(); snapshot != nil && snapshot.preMatchFields&missing != 0 {
			return true
		}
	}
	for i := range r.children {
		if r.children[i].missingPreMatchFields(missing) {
			return true
		}
	}
	return false
}
