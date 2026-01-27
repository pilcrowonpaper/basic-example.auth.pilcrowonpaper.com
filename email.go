package main

import (
	"context"
	"fmt"
)

type emailClientInterface interface {
	sendEmail(ctx context.Context, toEmailAddress string, subject string, body string) error
}

var stdoutEmailClient emailClientInterface = &stdoutEmailClientStruct{}

type stdoutEmailClientStruct struct{}

func (stdoutEmailClient *stdoutEmailClientStruct) sendEmail(ctx context.Context, toEmailAddress string, subject string, body string) error {
	template := `[Email] To: %s
Subject: %s

%s\n`
	fmt.Printf(template, toEmailAddress, subject, body)

	return nil
}
