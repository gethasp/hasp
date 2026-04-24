package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func secretAddInputs(args []string, prompt *secretPrompt) ([]secretInput, error) {
	if len(args) == 0 {
		out := make([]secretInput, 0)
		for {
			name, err := prompt.line("Key name")
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(name) == "" {
				return nil, errors.New("key name is required")
			}
			value, err := prompt.secretValue(name)
			if err != nil {
				return nil, err
			}
			out = append(out, secretInput{name: name, value: value})
			again, err := prompt.confirm("Add another", true)
			if err != nil {
				return nil, err
			}
			if !again {
				return out, nil
			}
		}
	}
	return secretInputsFromArgs(args, prompt)
}

func secretUpdateInputs(args []string, prompt *secretPrompt) ([]secretInput, error) {
	if len(args) == 0 {
		name, err := prompt.line("Key name")
		if err != nil {
			return nil, err
		}
		value, err := prompt.secretValue(name)
		if err != nil {
			return nil, err
		}
		return []secretInput{{name: name, value: value}}, nil
	}
	return secretInputsFromArgs(args, prompt)
}

func secretInputsFromArgs(args []string, prompt *secretPrompt) ([]secretInput, error) {
	out := make([]secretInput, 0, len(args))
	for _, arg := range args {
		name, value, ok := strings.Cut(arg, "=")
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, errors.New("secret name is required")
		}
		if ok {
			out = append(out, secretInput{name: name, value: []byte(value)})
			continue
		}
		prompted, err := prompt.secretValue(name)
		if err != nil {
			return nil, err
		}
		out = append(out, secretInput{name: name, value: prompted})
	}
	return out, nil
}

func secretNameInputs(args []string, prompt *secretPrompt, label string) ([]string, error) {
	if len(args) > 0 {
		names := make([]string, 0, len(args))
		for _, arg := range args {
			name := strings.TrimSpace(arg)
			if name == "" {
				return nil, errors.New("secret name is required")
			}
			names = append(names, name)
		}
		return names, nil
	}
	name, err := prompt.line(label)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("secret name is required")
	}
	return []string{name}, nil
}

func resolveSecretAddCollision(handle *store.Handle, name string, value []byte, onConflict string, prompt *secretPrompt) (string, []byte, string, error) {
	_, err := secretGetItemFn(handle, name)
	if err == nil {
		switch strings.TrimSpace(onConflict) {
		case "replace":
			return name, value, "updated", nil
		case "skip":
			return name, value, "skipped", nil
		case "":
			choice, renamed, promptErr := prompt.collision(name)
			if promptErr != nil {
				return "", nil, "", promptErr
			}
			switch choice {
			case "replace":
				return name, value, "updated", nil
			case "rename":
				return resolveSecretAddCollision(handle, renamed, value, "", prompt)
			case "skip":
				return name, value, "skipped", nil
			default:
				return "", nil, "", errors.New("secret add cancelled")
			}
		default:
			return "", nil, "", fmt.Errorf("secret %q already exists", name)
		}
	}
	if !errors.Is(err, store.ErrItemNotFound) {
		return "", nil, "", err
	}
	return name, value, "created", nil
}

func newSecretPrompt(stdin io.Reader, stdout io.Writer, stderr io.Writer) *secretPrompt {
	return &secretPrompt{
		reader: bufio.NewReader(stdin),
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
	}
}

func (p *secretPrompt) line(label string) (string, error) {
	if _, err := fmt.Fprintf(p.stdout, "%s: ", label); err != nil {
		return "", err
	}
	text, err := p.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

func (p *secretPrompt) secretValue(name string) ([]byte, error) {
	if !shouldMaskSecretValue(name) {
		text, err := p.line("Value")
		return []byte(text), err
	}
	if _, err := fmt.Fprint(p.stdout, "Value: "); err != nil {
		return nil, err
	}
	value, err := p.readHidden()
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (p *secretPrompt) confirm(label string, defaultYes bool) (bool, error) {
	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}
	answer, err := p.line(fmt.Sprintf("%s? %s", label, suffix))
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer == "" {
		return defaultYes, nil
	}
	return answer == "y" || answer == "yes", nil
}

func (p *secretPrompt) collision(name string) (string, string, error) {
	if _, err := fmt.Fprintf(p.stdout, "Secret %s already exists.\n\n1. Replace existing value\n2. Save under a different name\n3. Skip this secret\n4. Cancel\n\nChoice: ", name); err != nil {
		return "", "", err
	}
	choice, err := p.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", "", err
	}
	switch strings.TrimSpace(choice) {
	case "1":
		return "replace", "", nil
	case "2":
		renamed, err := p.line("New key name")
		return "rename", strings.TrimSpace(renamed), err
	case "3":
		return "skip", "", nil
	default:
		return "cancel", "", nil
	}
}

func (p *secretPrompt) readHidden() ([]byte, error) {
	file, ok := stdinFile(p.stdin)
	if !ok {
		text, err := p.reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		return []byte(strings.TrimSpace(text)), nil
	}
	if !secretIsCharDeviceFn(file) {
		text, err := p.reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		return []byte(strings.TrimSpace(text)), nil
	}
	if err := secretSetTTYEchoFn(file, false); err != nil {
		text, readErr := p.reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, readErr
		}
		return []byte(strings.TrimSpace(text)), nil
	}
	defer func() {
		_ = secretSetTTYEchoFn(file, true)
	}()
	text, err := p.reader.ReadString('\n')
	if _, printErr := fmt.Fprintln(p.stdout); printErr != nil && err == nil {
		err = printErr
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return []byte(strings.TrimSpace(text)), nil
}

func stdinFile(reader io.Reader) (*os.File, bool) {
	if reader == nil {
		return nil, false
	}
	if file, ok := reader.(*os.File); ok {
		return file, true
	}
	return nil, false
}

func isCharDevice(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func secretSetTTYEcho(file *os.File, enabled bool) error {
	arg := "-echo"
	if enabled {
		arg = "echo"
	}
	cmd := secretExecCommandFn("stty", arg)
	cmd.Stdin = file
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func shouldMaskSecretValue(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	return strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "TOKEN") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "KEY")
}
