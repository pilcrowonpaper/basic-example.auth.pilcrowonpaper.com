package main

import "fmt"

func sendSignupEmailAddressVerificationCodeEmail(emailAddress string, emailAddressVerificationCode string) error {
	fmt.Printf("To %s: Your email address verification code is %s.\n", emailAddress, emailAddressVerificationCode)
	return nil
}

func sendEmailAddressUpdateNewEmailAddressVerificationCodeEmail(emailAddress string, emailAddressVerificationCode string) error {
	fmt.Printf("To %s: Your email address verification code is %s.\n", emailAddress, emailAddressVerificationCode)
	return nil
}

func sendPasswordResetVerificationEmail(emailAddress string, verificationCode string) error {
	fmt.Printf("To %s: Your password reset one-time password is %s.\n", emailAddress, verificationCode)
	return nil
}

func sendEmailAddressUpdatedEmail(emailAddress string) error {
	fmt.Printf("To %s: Your account email address was recently updated.\n", emailAddress)
	return nil
}

func sendPasswordUpdatedEmail(emailAddress string) error {
	fmt.Printf("To %s: Your account password was recently updated.\n", emailAddress)
	return nil
}
