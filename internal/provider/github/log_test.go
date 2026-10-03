package github

import (
	"io"
	"log/slog"
)

func newTextLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }
