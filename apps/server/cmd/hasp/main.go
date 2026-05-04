package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app"
)

var exitFn = os.Exit
var testDaemonParentPollInterval = 100 * time.Millisecond

func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

const testDaemonParentPIDEnv = "HASP_TEST_DAEMON_PARENT_PID"

func main() {
	parentCtx, stopParent := contextWithTestDaemonParent(context.Background())
	defer stopParent()
	ctx, stop := signal.NotifyContext(parentCtx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	exitFn(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func contextWithTestDaemonParent(ctx context.Context) (context.Context, context.CancelFunc) {
	parentPID, err := strconv.Atoi(os.Getenv(testDaemonParentPIDEnv))
	if err != nil || parentPID <= 0 {
		return context.WithCancel(ctx)
	}
	parentCtx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(testDaemonParentPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-parentCtx.Done():
				return
			case <-ticker.C:
				if !processExists(parentPID) {
					cancel()
					return
				}
			}
		}
	}()
	return parentCtx, cancel
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if err := app.Run(ctx, args, stdin, stdout, stderr); err != nil {
		app.WriteCLIError(stderr, err, app.ArgsRequestJSON(args))
		return app.AppErrorExitCode(err)
	}
	return 0
}
