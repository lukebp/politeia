// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/util"
)

// Client provides a client for interacting with the politeiad API.
type Client struct {
	rpcHost string
	rpcUser string
	rpcPass string
	http    *http.Client
	pid     *identity.PublicIdentity
}

// ErrorReply represents the request body that is returned from politeaid when
// an error occurs. PluginID will only be populated if this is a plugin error.
type ErrorReply struct {
	PluginID     string
	ErrorCode    int
	ErrorContext []string
}

// Error represents a politeiad error. Error is returned anytime the politeiad
// is not a 200.
type Error struct {
	HTTPCode   int
	ErrorReply ErrorReply
}

// Error satisfies the error interface.
func (e Error) Error() string {
	if e.ErrorReply.PluginID != "" {
		return fmt.Sprintf("politeiad plugin error: %v %v %v",
			e.HTTPCode, e.ErrorReply.PluginID, e.ErrorReply.ErrorCode)
	}
	return fmt.Sprintf("politeiad error: %v %v",
		e.HTTPCode, e.ErrorReply.ErrorCode)
}

// makeReq makes a politeiad http request to the method and route provided,
// serializing the provided object as the request body, and returning a byte
// slice of the repsonse body. An Error is returned if politeiad responds with
// anything other than a 200 http status code.
func (c *Client) makeReq(ctx context.Context, method string, route string, v interface{}) ([]byte, error) {
	// Serialize body
	var (
		reqBody []byte
		err     error
	)
	if v != nil {
		reqBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	// Send request
	fullRoute := c.rpcHost + route
	req, err := http.NewRequestWithContext(ctx, method,
		fullRoute, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.rpcUser, c.rpcPass)
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	// Handle reply
	if r.StatusCode != http.StatusOK {
		var e ErrorReply
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&e); err != nil {
			return nil, fmt.Errorf("status code %v: %v", r.StatusCode, err)
		}
		return nil, Error{
			HTTPCode:   r.StatusCode,
			ErrorReply: e,
		}
	}

	respBody := util.ConvertBodyToByteArray(r.Body, false)
	return respBody, nil
}

// New returns a new politeiad client.
func New(rpcHost, rpcUser, rpcPass string, pid *identity.PublicIdentity) (*Client, error) {
	h, err := util.NewHTTPClient(false, "")
	if err != nil {
		return nil, err
	}
	return &Client{
		rpcHost: rpcHost,
		rpcUser: rpcUser,
		rpcPass: rpcPass,
		http:    h,
	}, nil
}