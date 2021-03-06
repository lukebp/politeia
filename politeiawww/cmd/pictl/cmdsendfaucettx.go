// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"github.com/decred/politeia/util"
)

// cmdSendFaucetTx uses the Decred testnet faucet to send the specified amount
// of DCR (in atoms) to the specified address.
type cmdSendFaucetTx struct {
	Args struct {
		Address       string `positional-arg-name:"address" required:"true"`
		Amount        uint64 `positional-arg-name:"amount" required:"true"`
		OverrideToken string `positional-arg-name:"overridetoken"`
	} `positional-args:"true"`
}

// Execute executes the cmdSendFaucetTx command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdSendFaucetTx) Execute(args []string) error {
	address := c.Args.Address
	atoms := c.Args.Amount
	dcr := float64(atoms) / 1e8

	txID, err := util.PayWithTestnetFaucet(context.Background(),
		cfg.FaucetHost, address, atoms, c.Args.OverrideToken)
	if err != nil {
		return err
	}

	switch {
	case cfg.Silent:
		// Keep quite
	case cfg.RawJSON:
		fmt.Printf(`{"txid":"%v"}`, txID)
		fmt.Printf("\n")
	default:
		fmt.Printf("Paid %v DCR to %v with tx %v\n", dcr, address, txID)
	}

	return nil
}

// sendFaucetTxHelpMsg is the help command message.
const sendFaucetTxHelpMsg = `sendfaucettx "address" "amount" "overridetoken"

Use the Decred testnet faucet to send DCR (in atoms) to an address. One atom is
one hundred millionth of a single DCR (0.00000001 DCR).

Arguments:
1. address          (string, required)   Receiving address
2. amount           (uint64, required)   Amount to send (in atoms)
3. overridetoken    (string, optional)   Override token for testnet faucet
`
