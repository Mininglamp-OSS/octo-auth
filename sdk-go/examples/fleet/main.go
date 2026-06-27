// Package main is a minimal octo-fleet integration sketch showing the
// scope-based route split that fleet uses: /v1/runtimes is for daemons
// (API key only); /v1/bots is for web users (session only). The SDK's
// Scope enum maps these directly.
//
// Actual fleet integration lands in PR-C2.
package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/Mininglamp-OSS/octo-auth/sdk-go/auth"
)

func main() {
	client, err := auth.New(auth.Options{ServerURL: os.Getenv("OCTO_SERVER_URL")})
	if err != nil {
		slog.Error("auth client", "err", err)
		os.Exit(1)
	}

	r := gin.Default()

	// Daemon endpoints: API key only. ScopeDaemon rejects session and
	// bot tokens with 403 AUTH_KIND_MISMATCH.
	daemon := r.Group("/v1", client.Middleware(auth.ScopeDaemon))
	{
		daemon.POST("/runtimes", func(c *gin.Context) {
			ownerUID := auth.GetLoginUID(c) // API-key owner
			c.JSON(http.StatusOK, gin.H{"owner_uid": ownerUID})
		})
	}

	// Web endpoints: session only. RequireSpaceMember fails closed on
	// X-Space-Id mismatch.
	web := r.Group("/v1", client.Middleware(auth.ScopeWeb), client.RequireSpaceMember())
	{
		web.GET("/bots", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"uid":   auth.GetLoginUID(c),
				"space": auth.GetSpaceID(c),
			})
		})
	}

	_ = r.Run(":8081")
}
