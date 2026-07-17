package octoauth

// NewFullMultiVerifier is the one-shot convenience constructor that stitches
// all three realms together behind a single [MultiVerifier]. It is the entry
// point recommended for services (like octo-fleet) that accept every
// credential kind.
//
// cfg is patched in place with defaults and shared across the three child
// verifiers so they use the same [Cache] and [MetricsCollector]. See design
// doc §4.2.
func NewFullMultiVerifier(cfg *Config) MultiVerifier {
	applyDefaults(cfg)
	return NewMultiVerifier(
		NewSessionVerifier(cfg),
		NewBotTokenVerifier(cfg),
		NewUserKeyVerifier(cfg),
	)
}
