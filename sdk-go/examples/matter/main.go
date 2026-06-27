// Package main is a minimal octo-matter integration sketch. It shows the
// shape an octo-matter service would adopt to replace its hand-rolled
// internal/auth/middleware.go with the octo-auth SDK.
//
// This is illustrative — actual octo-matter integration lands in PR-C1
// of the parent project's Stage C epic. Run-don't-build (the imports
// reference packages not present in this monorepo).
package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Mininglamp-OSS/octo-auth/sdk-go/auth"
	"github.com/Mininglamp-OSS/octo-auth/sdk-go/metrics"
)

func main() {
	client, err := auth.New(auth.Options{
		ServerURL: os.Getenv("OCTO_SERVER_URL"),
		Logger:    slog.Default(),
		Collector: metrics.NewPrometheusCollector(prometheus.DefaultRegisterer),
	})
	if err != nil {
		slog.Error("auth client", "err", err)
		os.Exit(1)
	}

	r := gin.Default()

	// Metrics endpoint for Prometheus scrape.
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Matter API routes — accept any token kind (matter callers include
	// human users via session token AND bots via bf_/app_ tokens), then
	// fail-closed on X-Space-Id via the SDK decorator.
	api := r.Group("/v1", client.Middleware(auth.ScopeAny), client.RequireSpaceMember())
	{
		api.GET("/matters", func(c *gin.Context) {
			uid := auth.GetLoginUID(c)
			space := auth.GetSpaceID(c)
			related := auth.GetRelatedUIDs(c)
			c.JSON(http.StatusOK, gin.H{
				"caller":       uid,
				"space":        space,
				"related_uids": related,
			})
		})
	}

	_ = r.Run(":8080")
}
