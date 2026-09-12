// Package tsa implements an RFC 3161 Time-Stamp Authority: request
// parsing and token generation, signed by its own identity issued by the
// pki module at bootstrap (see internal/bootstrap's generateTSALeaf and
// LoadTSAIssuer). Enable/disable via api.ModuleConfig.EnableTSA -- see
// docs/design.md, module 3.
package tsa
