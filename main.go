//go:build windows

package main

import (
	"context"
	"log/slog"
	"mini-soc/utils"
)

func main() {
	ctx := context.Background()

	auth, err := utils.GetAuth()
	if err != nil {
		slog.ErrorContext(ctx, "failed to get auth", "err", err)
	}

	StartListener(ctx, *auth)
}
