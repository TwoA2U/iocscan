package main

import (
	_ "embed"

	"github.com/TwoA2U/iocscan/cmd"
)

//go:embed web/index.html
var embeddedIndex []byte

func main() {
	cmd.SetEmbeddedUI(embeddedIndex)
	cmd.Execute()
}
