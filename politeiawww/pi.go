// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	piplugin "github.com/decred/politeia/plugins/pi"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/user"
)

func convertPropStateFromPi(s pi.PropStateT) piplugin.PropStateT {
	switch s {
	case pi.PropStateUnvetted:
		return piplugin.PropStateUnvetted
	case pi.PropStateVetted:
		return piplugin.PropStateVetted
	}
	return piplugin.PropStateInvalid
}

// newComment calls the pi plugin to add new comment.
func (p *politeiawww) piCommentNew(cn pi.CommentNew, usr *user.User) (*piplugin.CommentNewReply, error) {
	// Prep new comment payload
	ncp := piplugin.CommentNew{
		UUID:      usr.ID.String(),
		Token:     cn.Token,
		ParentID:  cn.ParentID,
		Comment:   cn.Comment,
		PublicKey: cn.PublicKey,
		Signature: cn.Signature,
		State:     convertPropStateFromPi(cn.State),
	}
	payload, err := piplugin.EncodeCommentNew(ncp)

	r, err := p.pluginCommand(piplugin.ID, piplugin.CmdCommentNew, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	cnr, err := piplugin.DecodeCommentNewReply([]byte(r))
	if err != nil {
		return nil, err
	}

	return cnr, nil
}
