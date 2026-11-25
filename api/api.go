// Package api is Kayra's contracts, <name>-<version>.yaml (system,
// catalog, authorization and events), and zz_generated.go, generated from
// them: their schemas as Go types, each API's Group and Roots, and
// Contracts. Edit a contract, then infrapi-cli app generate.
//
// The contracts are written for the domain infrapi.io: SetDomain moves
// them, their groups and roots, to Kayra's own.
package api

//go:generate infrapi-cli app generate
