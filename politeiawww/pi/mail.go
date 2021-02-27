// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"text/template"

	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
)

const (
	// TODO GUI links needs to be updated
	// The following routes are used in notification emails to direct
	// the user to the correct GUI pages.
	guiRouteRecordDetails = "/record/{token}"
	guiRouteRecordComment = "/record/{token}/comments/{id}"
)

type proposalNew struct {
	Username string // Author username
	Name     string // Proposal name
	Link     string // GUI proposal details URL
}

var proposalNewText = `
A new proposal has been submitted on Politeia by {{.Username}}:

{{.Name}}
{{.Link}}
`

var proposalNewTmpl = template.Must(
	template.New("proposalNew").Parse(proposalNewText))

func (p *Pi) mailNtfnProposalNew(token, name, username string, emails []string) error {
	route := strings.Replace(guiRouteRecordDetails, "{token}", token, 1)
	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tmplData := proposalNew{
		Username: username,
		Name:     name,
		Link:     u.String(),
	}

	subject := "New Proposal Submitted"
	body, err := populateTemplate(proposalNewTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.mail.SendTo(subject, body, emails)
}

type proposalEdit struct {
	Name     string // Proposal name
	Version  string // Proposal version
	Username string // Author username
	Link     string // GUI proposal details URL
}

var proposalEditText = `
A proposal by {{.Username}} has just been edited:

{{.Name}} (Version {{.Version}})
{{.Link}}
`

var proposalEditTmpl = template.Must(
	template.New("proposalEdit").Parse(proposalEditText))

func (p *Pi) mailNtfnProposalEdit(token, version, name, username string, emails []string) error {
	route := strings.Replace(guiRouteRecordDetails, "{token}", token, 1)
	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tmplData := proposalEdit{
		Name:     name,
		Version:  version,
		Username: username,
		Link:     u.String(),
	}

	subject := "Proposal Edited"
	body, err := populateTemplate(proposalEditTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.mail.SendTo(subject, body, emails)
}

type proposalPublished struct {
	Name string // Proposal name
	Link string // GUI proposal details URL
}

var proposalPublishedTmpl = template.Must(
	template.New("proposalPublished").Parse(proposalPublishedText))

var proposalPublishedText = `
A new proposal has just been published on Politeia.

{{.Name}}
{{.Link}}
`

func (p *Pi) mailNtfnProposalSetStatus(token, name string, status rcv1.RecordStatusT, emails []string) error {
	route := strings.Replace(guiRouteRecordDetails, "{token}", token, 1)
	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	var (
		subject string
		body    string
	)
	switch status {
	case rcv1.RecordStatusPublic:
		subject = "New Proposal Published"
		tmplData := proposalPublished{
			Name: name,
			Link: u.String(),
		}
		body, err = populateTemplate(proposalPublishedTmpl, tmplData)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("no mail ntfn for status %v", status)
	}

	return p.mail.SendTo(subject, body, emails)
}

type proposalPublishedToAuthor struct {
	Name string // Proposal name
	Link string // GUI proposal details URL
}

var proposalPublishedToAuthorText = `
Your proposal has just been made public on Politeia!

Your proposal has now entered the discussion phase where the community can leave comments and provide feedback.  Be sure to keep an eye out for new comments and to answer any questions that the community may have.  You can edit your proposal at any point prior to the start of voting.

Once you feel that enough time has been given for discussion you may authorize the vote to commence on your proposal.  An admin is not able to start the voting process until you explicitly authorize it.  You can authorize a proposal vote by opening the proposal page and clicking on the authorize vote button.

{{.Name}}
{{.Link}}

If you have any questions, drop by the proposals channel on matrix.
https://chat.decred.org/#/room/#proposals:decred.org
`
var proposalPublishedToAuthorTmpl = template.Must(
	template.New("proposalPublishedToAuthor").
		Parse(proposalPublishedToAuthorText))

type proposalCensoredToAuthor struct {
	Name   string // Proposal name
	Reason string // Reason for censoring
}

var proposalCensoredToAuthorText = `
Your proposal on Politeia has been censored.

{{.Name}}
Reason: {{.Reason}}
`

var proposalCensoredToAuthorTmpl = template.Must(
	template.New("proposalCensoredToAuthor").
		Parse(proposalCensoredToAuthorText))

func (p *Pi) mailNtfnProposalSetStatusToAuthor(token, name string, status rcv1.RecordStatusT, reason, authorEmail string) error {
	route := strings.Replace(guiRouteRecordDetails, "{token}", token, 1)
	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	var (
		subject string
		body    string
	)
	switch status {
	case rcv1.RecordStatusPublic:
		subject = "Your Proposal Has Been Published"
		tmplData := proposalPublishedToAuthor{
			Name: name,
			Link: u.String(),
		}
		body, err = populateTemplate(proposalPublishedToAuthorTmpl, tmplData)
		if err != nil {
			return err
		}

	case rcv1.RecordStatusCensored:
		subject = "Your Proposal Has Been Censored"
		tmplData := proposalCensoredToAuthor{
			Name:   name,
			Reason: reason,
		}
		body, err = populateTemplate(proposalCensoredToAuthorTmpl, tmplData)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("no author notification for prop status %v", status)
	}

	return p.mail.SendTo(subject, body, []string{authorEmail})
}

func populateTemplate(tpl *template.Template, tplData interface{}) (string, error) {
	var buf bytes.Buffer
	err := tpl.Execute(&buf, tplData)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
