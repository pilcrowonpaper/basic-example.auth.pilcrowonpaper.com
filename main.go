package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "embed"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

const databaseFilename = "main.db"

//go:embed schema.sql
var schemaSQLScript string

func main() {
	portString := os.Getenv("PORT")
	if portString == "" {
		portString = "3000"
	}
	httpsEnvValue := os.Getenv("HTTPS")
	if httpsEnvValue == "" {
		httpsEnvValue = "0"
	}
	awsSESEnvValue := os.Getenv("AWS_SES")
	if awsSESEnvValue == "" {
		awsSESEnvValue = "0"
	}
	awsAccessKeyEnvValue := os.Getenv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKeyEnvValue := os.Getenv("AWS_SECRET_ACCESS_KEY")
	awsRegionEnvValue := os.Getenv("AWS_REGION")
	if awsRegionEnvValue == "" {
		awsRegionEnvValue = "us-east-1"
	}
	awsSESEmailAddressEnvValue := os.Getenv("AWS_SES_EMAIL_ADDRESS")
	logsEnvValue := os.Getenv("LOGS")
	if logsEnvValue == "" {
		logsEnvValue = "action_error,background_job"
	}

	port, err := parseNonNegativeIntegerString(portString)
	if err != nil {
		log.Fatalf("invalid PORT environment variable: %s", err.Error())
	}

	var emailClient emailClientInterface
	if awsSESEnvValue == "1" {
		staticProvider := credentials.NewStaticCredentialsProvider(awsAccessKeyEnvValue, awsSecretAccessKeyEnvValue, "")

		cfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithRegion(awsRegionEnvValue),
			config.WithCredentialsProvider(staticProvider),
		)
		if err != nil {
			log.Fatalf("failed to load config, %v", err)
		}

		awsSESClient := sesv2.NewFromConfig(cfg)

		emailClient = newAWSSESEmailClient(awsSESClient, awsSESEmailAddressEnvValue)
	} else {
		emailClient = stdoutEmailClient
	}

	serverLogging := serverLoggingStruct{}
	logsEnvValues := strings.SplitSeq(logsEnvValue, ",")
	for logsEnvValue := range logsEnvValues {
		if logsEnvValue == "action_event" {
			serverLogging.actionEvent = true
		} else if logsEnvValue == "action_error" {
			serverLogging.actionError = true
		} else if logsEnvValue == "background_job" {
			serverLogging.backgroundJob = true
		} else if logsEnvValue == "action_result" {
			serverLogging.actionResult = true
		} else {
			log.Fatalf("unknown LOGS environment variable value item: %s", logsEnvValue)
		}
	}

	err = setUpDatabase()
	if err != nil {
		log.Fatalf("failed to set up server: %s\n", err.Error())
	}

	serverFlags := serverFlagsStruct{
		https: httpsEnvValue == "1",
	}
	server, err := createServer(emailClient, serverFlags, serverLogging)
	if err != nil {
		log.Fatalf("failed to create server: %s\n", err.Error())
	}

	go func() {
		const backgroundJob = "clear_data"

		for {
			now := time.Now().UTC()
			nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)

			time.Sleep(time.Until(nextMidnight))

			runId := generateLongItemId()
			server.logBackgroundJobRun(runId, backgroundJob)

			err := server.deleteAllUsers()
			if err != nil {
				errorMessage := fmt.Sprintf("failed to delete all users: %s", err.Error())
				server.logBackgroundJobError(runId, errorMessage)
			}

			server.userPasswordAuthenticationRateLimit.Clear()
			server.emailAddressVerificationRateLimit.Clear()
			server.userPasswordResetOneTimePasswordVerificationRateLimit.Clear()
			server.emailRateLimit.Clear()

			server.logBackgroundJobRunCompletion(runId)
		}
	}()

	fmt.Printf("Starting server on port %d...\n", port)
	address := fmt.Sprintf(":%d", port)
	err = http.ListenAndServe(address, server)
	if err != nil {
		log.Fatalf("failed to start server: %s", err.Error())
	}
}

func generateItemId() string {
	idBytes := make([]byte, 10)
	rand.Read(idBytes)
	verificationCode := base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789").EncodeToString(idBytes)
	return verificationCode
}

func generateLongItemId() string {
	idBytes := make([]byte, 20)
	rand.Read(idBytes)
	verificationCode := base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789").EncodeToString(idBytes)
	return verificationCode
}

func generateOneTimePassword() string {
	idBytes := make([]byte, 10)
	rand.Read(idBytes)
	verificationCode := base32.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZ23456789").EncodeToString(idBytes)
	return verificationCode
}

func formatOneTimePassword(oneTimePassword string) string {
	stringBytes := make([]byte, 19)
	stringBytes[0] = oneTimePassword[0]
	stringBytes[1] = oneTimePassword[1]
	stringBytes[2] = oneTimePassword[2]
	stringBytes[3] = oneTimePassword[3]
	stringBytes[4] = '-'
	stringBytes[5] = oneTimePassword[4]
	stringBytes[6] = oneTimePassword[5]
	stringBytes[7] = oneTimePassword[6]
	stringBytes[8] = oneTimePassword[7]
	stringBytes[9] = '-'
	stringBytes[10] = oneTimePassword[8]
	stringBytes[11] = oneTimePassword[9]
	stringBytes[12] = oneTimePassword[10]
	stringBytes[13] = oneTimePassword[11]
	stringBytes[14] = '-'
	stringBytes[15] = oneTimePassword[12]
	stringBytes[16] = oneTimePassword[13]
	stringBytes[17] = oneTimePassword[14]
	stringBytes[18] = oneTimePassword[15]
	return string(stringBytes)
}

func generateEmailAddressVerificationCode() string {
	for {
		randomBytes := make([]byte, 4)
		rand.Read(randomBytes)
		randomUint := binary.BigEndian.Uint32(randomBytes)
		randomUint >>= 5
		if randomUint < 100_000_000 {
			stringBytes := make([]byte, 8)
			stringBytes[0] = byte((randomUint/10_000_000)%10 + '0')
			stringBytes[1] = byte((randomUint/1_000_000)%10 + '0')
			stringBytes[2] = byte((randomUint/100_000)%10 + '0')
			stringBytes[3] = byte((randomUint/10_000)%10 + '0')
			stringBytes[4] = byte((randomUint/1_000)%10 + '0')
			stringBytes[5] = byte((randomUint/100)%10 + '0')
			stringBytes[6] = byte((randomUint/10)%10 + '0')
			stringBytes[7] = byte((randomUint)%10 + '0')
			return string(stringBytes)
		}
	}
}

func formatEmailAddressVerificationCode(verificationCode string) string {
	stringBytes := make([]byte, 9)
	stringBytes[0] = verificationCode[0]
	stringBytes[1] = verificationCode[1]
	stringBytes[2] = verificationCode[2]
	stringBytes[3] = verificationCode[3]
	stringBytes[4] = '-'
	stringBytes[5] = verificationCode[4]
	stringBytes[6] = verificationCode[5]
	stringBytes[7] = verificationCode[6]
	stringBytes[8] = verificationCode[7]
	return string(stringBytes)
}

func parseNonNegativeIntegerString(s string) (int, error) {
	if len(s) == 0 {
		return 0, errors.New("empty string")
	}
	if s == "0" {
		return 0, nil
	}
	result := 0
	chars := []rune(s)
	if chars[0] == '0' {
		return 0, errors.New("leading zero")
	}
	for _, char := range chars {
		if char >= '0' && char <= '9' {
			result = result*10 + int(char-'0')
		} else {
			return 0, errors.New("invalid character")
		}
	}
	return result, nil
}
