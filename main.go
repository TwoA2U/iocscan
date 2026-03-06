package main

import (
	"embed"

	"github.com/TwoA2U/iocscan/cmd"
)

//go:embed all:web
var embeddedFS embed.FS

func main() {
	cmd.SetEmbeddedUI(embeddedFS)
	cmd.Execute()
}
