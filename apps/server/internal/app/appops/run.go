package appops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

func appRunHandler(ctx context.Context, deps Deps, args []string, stdout, stderr io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := newFlagSet(deps, "app run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("usage: hasp app run <name> [args...]")
	}
	if deps.OpenVault == nil {
		return errors.New("appops: OpenVault dep not wired")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	consumer, err := deps.StoreGetApp(handle, name)
	if err != nil {
		return err
	}
	var s Starter
	if deps.AppNewStarter != nil {
		s, err = deps.AppNewStarter()
		if err != nil {
			return err
		}
	}
	command := append([]string{}, consumer.Command...)
	command = append(command, fs.Args()...)
	if deps.AppExecuteConsumer == nil {
		return errors.New("appops: AppExecuteConsumer dep not wired")
	}
	runResult, err := deps.AppExecuteConsumer(ctx, handle, consumer, command, stdout, stderr, s, "run")
	if err != nil {
		return err
	}
	if runResult.ExitCode != 0 {
		return fmt.Errorf("command exited with code %d", runResult.ExitCode)
	}
	return nil
}

func appShellHandler(ctx context.Context, deps Deps, args []string, stdout, stderr io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := newFlagSet(deps, "app shell", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("usage: hasp app shell <name> [shell args...]")
	}
	if deps.OpenVault == nil {
		return errors.New("appops: OpenVault dep not wired")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	consumer, err := deps.StoreGetApp(handle, name)
	if err != nil {
		return err
	}
	var s Starter
	if deps.AppNewStarter != nil {
		s, err = deps.AppNewStarter()
		if err != nil {
			return err
		}
	}
	shell := ""
	if deps.AppUserShell != nil {
		shell = strings.TrimSpace(deps.AppUserShell())
	}
	if shell == "" {
		shell = "/bin/sh"
	}
	command := []string{shell, "-l"}
	command = append(command, fs.Args()...)
	if deps.AppExecuteConsumer == nil {
		return errors.New("appops: AppExecuteConsumer dep not wired")
	}
	runResult, err := deps.AppExecuteConsumer(ctx, handle, consumer, command, stdout, stderr, s, "shell")
	if err != nil {
		return err
	}
	if runResult.ExitCode != 0 {
		return fmt.Errorf("command exited with code %d", runResult.ExitCode)
	}
	return nil
}
