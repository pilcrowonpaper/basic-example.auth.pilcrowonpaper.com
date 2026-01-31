package main

import (
	"fmt"
)

func (server *serverStruct) sendSignupEmailAddressVerificationCodeEmail(emailAddress string, emailAddressVerificationCode string) error {
	subject := "Verify your email address"
	bodyTemplate := `Your email address verification code is: %s

Do not share this code with anyone. If you didn't request this, you can safely ignore this email.

Basic auth example: https://basic-example.auth.pilcrowonpaper.com`
	body := fmt.Sprintf(bodyTemplate, emailAddressVerificationCode)

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendEmailAddressUpdateNewEmailAddressVerificationCodeEmail(emailAddress string, emailAddressVerificationCode string) error {
	subject := "Verify your new email address"
	bodyTemplate := `Your email address verification code is: %s

Do not share this code with anyone. If you didn't request this, you can safely ignore this email.

Basic auth example: https://basic-example.auth.pilcrowonpaper.com`
	body := fmt.Sprintf(bodyTemplate, emailAddressVerificationCode)

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendPasswordResetOneTimePasswordEmail(emailAddress string, oneTimePassword string) error {
	subject := "Verify your identity"
	bodyTemplate := `Your password reset one-time password is: %s

Do not share this code with anyone. If you didn't request this, you can safely ignore this email.

Basic auth example: https://basic-example.auth.pilcrowonpaper.com`
	body := fmt.Sprintf(bodyTemplate, oneTimePassword)

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendSignedInEmail(emailAddress string) error {
	subject := "New sign-in to your account"
	body := `We detected a recent login to your account. If this wasn't you, please secure your account by resetting your password immediately.

Basic auth example: https://basic-example.auth.pilcrowonpaper.com`

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendEmailAddressUpdatedEmail(emailAddress string) error {
	subject := "Your account's email address was recently updated"
	body := `This email address is no longer tied to your account.

Basic auth example: https://basic-example.auth.pilcrowonpaper.com`

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendPasswordUpdatedEmail(emailAddress string) error {
	subject := "Your account's password was recently updated"
	body := `Your account password was recently updated. If you did not make this change, please secure your account by resetting your password immediately.

Basic auth example: https://basic-example.auth.pilcrowonpaper.com`

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}
