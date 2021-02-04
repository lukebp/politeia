// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// cmdCommentVotes retrieves the comment upvotes/downvotes for a user on a
// record.
type cmdCommentVotes struct {
	Args struct {
		Token  string `positional-arg-name:"token" required:"true"`
		UserID string `positional-arg-name:"userid"`
	} `positional-args:"true"`
	Me bool `long:"me" optional:"true"`
}

/*
// Execute executes the cmdCommentVotes command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdCommentVotes) Execute(args []string) error {
	token := c.Args.Token
	userID := c.Args.UserID

	if userID == "" && !c.Me {
		return fmt.Errorf("you must either provide a user id or use " +
			"the --me flag to use the user ID of the logged in user")
	}

	// Get user ID of logged in user if specified
	if c.Me {
		lr, err := client.Me()
		if err != nil {
			return err
		}
		userID = lr.UserID
	}

	cvr, err := client.CommentVotes(pi.CommentVotes{
		Token:  token,
		State:  pi.PropStateVetted,
		UserID: userID,
	})
	if err != nil {
		return err
	}
	return shared.PrintJSON(cvr)
}
*/

// commentVotesHelpMsg is printed to stdout by the help command.
const commentVotesHelpMsg = `commentvotes "token" "userid"

Get the provided user comment upvote/downvotes for a proposal.

Arguments:
1. token       (string, required)  Proposal censorship token
2. userid      (string, required)  User ID

Flags:
  --me   (bool, optional)  Use the user ID of the logged in user
`