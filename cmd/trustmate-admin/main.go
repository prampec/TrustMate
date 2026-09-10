// Command trustmate-admin will be the operator CLI for one-time or
// operator-only actions (root CA init, profile reload, manual revocation,
// key rotation), talking to the same REST API a human would otherwise use
// a GUI for. Not implemented yet — see docs/design.md phase 3.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "trustmate-admin: not implemented yet (see docs/design.md, phase 3)")
	os.Exit(1)
}
