package main

import (
	"fmt"
)

func (server *serverStruct) sendSignupEmailAddressVerificationCodeEmail(emailAddress string, emailAddressVerificationCode string) error {
	formattedEmailAddressVerificationCode := formatEmailAddressVerificationCode(emailAddressVerificationCode)

	subject := "Verify your account email address"
	bodyTemplate := `Your email address verification code is: %s

Do not share this code with anyone. If you didn't request this, you can safely ignore this email.

Basic auth example: https://basic-example.auth.pilcrowonpaper.com`
	body := fmt.Sprintf(bodyTemplate, formattedEmailAddressVerificationCode)

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendEmailAddressUpdateNewEmailAddressVerificationCodeEmail(emailAddress string, emailAddressVerificationCode string) error {
	formattedEmailAddressVerificationCode := formatEmailAddressVerificationCode(emailAddressVerificationCode)

	subject := "Verify your new account email address"
	bodyTemplate := `Your email address verification code is: %s

Do not share this code with anyone. If you didn't request this, you can safely ignore this email.

Basic auth example: https://basic-example.auth.pilcrowonpaper.com`
	body := fmt.Sprintf(bodyTemplate, formattedEmailAddressVerificationCode)

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendPasswordResetEmailCodeEmail(emailAddress string, code string) error {
	formattedCode := formatPasswordResetCode(code)

	subject := "Reset your account password"
	bodyTemplate := `Your password reset code is: %s

Do not share this code with anyone. If you didn't request this, you can safely ignore this email.

Basic auth example: https://basic-example.auth.pilcrowonpaper.com`
	body := fmt.Sprintf(bodyTemplate, formattedCode)

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
	subject := "Your account email address was recently updated"
	body := `This email address is no longer tied to your account.

Basic auth example: https://basic-example.auth.pilcrowonpaper.com`

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}

func (server *serverStruct) sendPasswordUpdatedEmail(emailAddress string) error {
	subject := "Your account password was recently updated"
	body := `Your account password was recently updated. If you did not make this change, please secure your account by resetting your password immediately.

Basic auth example: https://basic-example.auth.pilcrowonpaper.com`

	err := server.emailClient.sendEmail(emailAddress, subject, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %s", err.Error())
	}
	return nil
}
