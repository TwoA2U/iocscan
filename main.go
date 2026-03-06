package main

import (
	"embed"
	"io/fs"

	"github.com/TwoA2U/iocscan/cmd"
)

//go:embed all:web
var embeddedWeb embed.FS

func main() {
	// Strip the "web/" prefix so the embedded FS root is the web/ directory
	// itself — http.FileServer will then serve index.html at "/" correctly.
	sub, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		panic(err)
	}
	cmd.SetEmbeddedUI(sub)
	cmd.Execute()
}
