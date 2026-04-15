package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/gethasp/hasp/apps/server/internal/app"
)

var exitFn = os.Exit

func main() {
	exitFn(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if err := app.Run(ctx, args, stdin, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	return 0
}
