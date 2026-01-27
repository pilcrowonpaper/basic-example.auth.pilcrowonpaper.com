package main

import (
	"fmt"
	"time"

	"github.com/pilcrowonpaper/go-json"
)

func (server *serverStruct) logActionSuccessResult(requestId string, actionName string) {
	if !server.logging.actionResult {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "action_success_result")
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSONBuilder.AddString("request_id", requestId)
	logJSONBuilder.AddJSON("action", actionName)
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

func (server *serverStruct) logActionErrorResult(requestId string, actionName string, errorCode string) {
	if !server.logging.actionResult {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "action_error_result")
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSONBuilder.AddString("request_id", requestId)
	logJSONBuilder.AddJSON("action", actionName)
	logJSONBuilder.AddJSON("error_code", errorCode)
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

func (server *serverStruct) logActionError(requestId string, errorMessage string) {
	if !server.logging.actionError {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "action_error")
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSONBuilder.AddString("request_id", requestId)
	logJSONBuilder.AddJSON("message", errorMessage)
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

func (server *serverStruct) logBackgroundJobRun(runId string, backgroundJobName string) {
	if !server.logging.backgroundJob {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "background_job_run")
	logJSONBuilder.AddString("run_id", runId)
	logJSONBuilder.AddString("background_job", backgroundJobName)
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

func (server *serverStruct) logBackgroundJobError(runId string, errorMessage string) {
	if !server.logging.backgroundJob {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "background_job_error")
	logJSONBuilder.AddString("run_id", runId)
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSONBuilder.AddJSON("message", errorMessage)
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

func (server *serverStruct) logBackgroundJobRunCompletion(runId string) {
	if !server.logging.backgroundJob {
		return
	}

	now := time.Now()

	logJSONBuilder := json.NewObjectBuilder(loggingJSONStringCharacterEscapingBehavior)
	logJSONBuilder.AddString("type", "background_job_run_completion")
	logJSONBuilder.AddString("run_id", runId)
	logJSONBuilder.AddInt64("timestamp", now.Unix())
	logJSON := logJSONBuilder.Done()

	fmt.Println(logJSON)
}

var loggingJSONStringCharacterEscapingBehavior json.StringCharacterEscapingBehaviorInterface = loggingJSONStringCharacterEscapingBehaviorStruct{}

type loggingJSONStringCharacterEscapingBehaviorStruct struct{}

func (loggingJSONStringCharacterEscapingBehaviorStruct) UseCharacter(r rune) bool {
	return r != '\n'
}

func (loggingJSONStringCharacterEscapingBehaviorStruct) UseShorthandEscapeSequence(_ rune) bool {
	return true
}
