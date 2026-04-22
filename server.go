package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"server/ratelimit"
	"strings"
	"time"

	"golang.org/x/sync/semaphore"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type serverStruct struct {
	emailClient emailClientInterface

	databaseReadConnectionPool  *sqlitex.Pool
	databaseWriteConnectionPool *sqlitex.Pool
	cpuIntensiveSemaphore       *semaphore.Weighted
	https                       bool

	logging serverLoggingStruct

	userPasswordAuthenticationRateLimit        *ratelimit.LimitStruct
	emailAddressVerificationRateLimit          *ratelimit.LimitStruct
	userPasswordResetCodeVerificationRateLimit *ratelimit.LimitStruct
	emailRateLimit                             *ratelimit.LimitStruct
	requestRateLimit                           *ratelimit.LimitStruct
}

type serverLoggingStruct struct {
	internalError bool
	backgroundJob bool
	actionResult  bool
	requestEmail  bool
	requestEvent  bool
}

type serverFlagsStruct struct {
	https bool
}

func createServer(emailClient emailClientInterface, flags serverFlagsStruct, logging serverLoggingStruct) (*serverStruct, error) {
	databaseFilename := "main.db"

	databaseReadConnectionPool, err := sqlitex.NewPool(databaseFilename, sqlitex.PoolOptions{
		Flags:    sqlite.OpenReadWrite | sqlite.OpenWAL,
		PoolSize: runtime.NumCPU(),
		PrepareConn: func(conn *sqlite.Conn) error {
			err := sqlitex.ExecuteTransient(conn, "PRAGMA foreign_keys = ON", nil)
			if err != nil {
				return fmt.Errorf("failed to enable foreign keys: %s", err.Error())
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sqlite read connection pool: %s", err.Error())
	}

	databaseWriteConnectionPool, err := sqlitex.NewPool(databaseFilename, sqlitex.PoolOptions{
		Flags:    sqlite.OpenReadWrite | sqlite.OpenWAL,
		PoolSize: 1,
		PrepareConn: func(conn *sqlite.Conn) error {
			err := sqlitex.ExecuteTransient(conn, "PRAGMA foreign_keys = ON", nil)
			if err != nil {
				return fmt.Errorf("failed to enable foreign keys: %s", err.Error())
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sqlite write connection pool: %s", err.Error())
	}

	cpuIntensiveSemaphore := semaphore.NewWeighted(int64(runtime.NumCPU()))

	userPasswordAuthenticationRateLimit := ratelimit.NewLimit(1_000, 5, time.Minute)
	emailAddressVerificationRateLimit := ratelimit.NewLimit(1_000, 5, time.Minute)
	userPasswordResetCodeVerificationRateLimit := ratelimit.NewLimit(1_000, 5, time.Minute)
	emailRateLimit := ratelimit.NewLimit(1_000, 5, 30*time.Minute)
	requestRateLimit := ratelimit.NewLimit(1_000, 100, time.Second)

	server := &serverStruct{
		emailClient:                                emailClient,
		databaseReadConnectionPool:                 databaseReadConnectionPool,
		databaseWriteConnectionPool:                databaseWriteConnectionPool,
		cpuIntensiveSemaphore:                      cpuIntensiveSemaphore,
		https:                                      flags.https,
		logging:                                    logging,
		userPasswordAuthenticationRateLimit:        userPasswordAuthenticationRateLimit,
		emailAddressVerificationRateLimit:          emailAddressVerificationRateLimit,
		userPasswordResetCodeVerificationRateLimit: userPasswordResetCodeVerificationRateLimit,
		emailRateLimit:                             emailRateLimit,
		requestRateLimit:                           requestRateLimit,
	}
	return server, nil
}

func (server *serverStruct) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			// Just kill the server if it panics

			stack := debug.Stack()
			fmt.Fprintf(os.Stderr, "%v\n", err)
			fmt.Fprintf(os.Stderr, "%s\n", stack)
			os.Exit(1)
		}
	}()

	requestId := r.Header.Get("X-Railway-Request-Id")
	if requestId == "" {
		requestId = generateLongItemId()
	}

	clientIPAddress := r.Header.Get("CF-Connecting-IP")
	if clientIPAddress != "" {
		rateLimitAllowed := server.requestRateLimit.Consume(clientIPAddress)
		if !rateLimitAllowed {
			w.WriteHeader(429)
			return
		}
	}

	pathParts := strings.Split(r.URL.Path, "/")[1:]

	// Remove single trailing slash
	if len(pathParts) > 0 && pathParts[len(pathParts)-1] == "" {
		pathParts = pathParts[:len(pathParts)-1]
	}

	// GET /
	if len(pathParts) == 0 && r.Method == "GET" {
		server.homePageRoute(w, r, requestId, clientIPAddress)
		return
	}

	// /sign-up
	if len(pathParts) > 0 && pathParts[0] == "sign-up" {
		// GET /sign-up
		if len(pathParts) == 1 && r.Method == "GET" {
			server.signUpPageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// GET /sign-up/verify-email-address
		if len(pathParts) == 2 && pathParts[1] == "verify-email-address" && r.Method == "GET" {
			server.verifySignupEmailAddressPageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// GET /sign-up/set-password
		if len(pathParts) == 2 && pathParts[1] == "set-password" && r.Method == "GET" {
			server.setSignupPasswordPageRoute(w, r, requestId, clientIPAddress)
			return
		}
	}

	// GET /sign-in
	if len(pathParts) == 1 && pathParts[0] == "sign-in" && r.Method == "GET" {
		server.signInPageRoute(w, r, requestId, clientIPAddress)
		return
	}

	// GET /account
	if len(pathParts) == 1 && pathParts[0] == "account" && r.Method == "GET" {
		server.accountPageRoute(w, r, requestId, clientIPAddress)
		return
	}

	// /update-password
	if len(pathParts) > 0 && pathParts[0] == "update-password" {
		// GET /update-password/verify-password
		if len(pathParts) == 2 && pathParts[1] == "verify-password" && r.Method == "GET" {
			server.verifyPasswordUpdateUserPasswordPageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// GET /update-password/set-new-password
		if len(pathParts) == 2 && pathParts[1] == "set-new-password" && r.Method == "GET" {
			server.setPasswordUpdateNewPasswordPageRoute(w, r, requestId, clientIPAddress)
			return
		}
	}

	// /update-email-address
	if len(pathParts) > 0 && pathParts[0] == "update-email-address" {
		// GET /update-email-address/verify-password
		if len(pathParts) == 2 && pathParts[1] == "verify-password" && r.Method == "GET" {
			server.verifyEmailAddressUpdateUserPasswordPageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// GET /update-email-address/set-new-email-address
		if len(pathParts) == 2 && pathParts[1] == "set-new-email-address" && r.Method == "GET" {
			server.setEmailAddressUpdateNewEmailAddressPageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// GET /update-email-address/verify-new-email-address
		if len(pathParts) == 2 && pathParts[1] == "verify-new-email-address" && r.Method == "GET" {
			server.verifyEmailAddressUpdateNewEmailAddressPageRoute(w, r, requestId, clientIPAddress)
			return
		}
	}

	// /delete-account
	if len(pathParts) > 0 && pathParts[0] == "delete-account" {
		// GET /delete-account/verify-password
		if len(pathParts) == 2 && pathParts[1] == "verify-password" && r.Method == "GET" {
			server.verifyAccountDeletionUserPasswordPageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// GET /delete-account/confirm
		if len(pathParts) == 2 && pathParts[1] == "confirm" && r.Method == "GET" {
			server.confirmAccountDeletionPageRoute(w, r, requestId, clientIPAddress)
			return
		}
	}

	// /reset-password
	if len(pathParts) > 0 && pathParts[0] == "reset-password" {
		// GET /reset-password
		if len(pathParts) == 1 && r.Method == "GET" {
			server.resetPasswordPageRoute(w, requestId, clientIPAddress)
			return
		}

		// GET /reset-password/verify-code
		if len(pathParts) == 2 && pathParts[1] == "verify-code" && r.Method == "GET" {
			server.verifyPasswordResetCodePageRoute(w, r, requestId, clientIPAddress)
			return
		}

		// GET /reset-password/set-new-password
		if len(pathParts) == 2 && pathParts[1] == "set-new-password" && r.Method == "GET" {
			server.setPasswordResetNewPasswordPageRoute(w, r, requestId, clientIPAddress)
			return
		}
	}

	// POST /action
	if len(pathParts) == 1 && pathParts[0] == "action" && r.Method == "POST" {
		server.actionRoute(w, r, requestId, clientIPAddress)
		return
	}

	w.WriteHeader(404)
	w.Write([]byte("The page you're looking for doesn't exist."))
}
