package octoauth

// Clone returns a deep copy of p safe for the caller to mutate without
// affecting other references (notably any cached *Principal that verifiers
// share across concurrent calls).
//
// The three reference-typed fields — RelatedUIDs, Context.Spaces, and
// Context.OwnedBotsBySpace — are copied element-wise; all other fields are
// value types and are shallow-copied by struct assignment.
//
// Clone is nil-safe: (*Principal)(nil).Clone() returns nil.
func (p *Principal) Clone() *Principal {
	if p == nil {
		return nil
	}
	dst := *p
	if p.RelatedUIDs != nil {
		dst.RelatedUIDs = append([]string(nil), p.RelatedUIDs...)
	}
	dst.Context = p.Context.clone()
	return &dst
}

// clone returns a deep copy of the PrincipalContext. Called by
// [Principal.Clone]; kept unexported since the middleware layer only ever
// needs to clone through Principal.
func (c PrincipalContext) clone() PrincipalContext {
	dst := c
	if c.Spaces != nil {
		dst.Spaces = append([]string(nil), c.Spaces...)
	}
	if c.OwnedBotsBySpace != nil {
		dst.OwnedBotsBySpace = make(map[string][]string, len(c.OwnedBotsBySpace))
		for k, v := range c.OwnedBotsBySpace {
			if v == nil {
				dst.OwnedBotsBySpace[k] = nil
				continue
			}
			dst.OwnedBotsBySpace[k] = append([]string(nil), v...)
		}
	}
	return dst
}
