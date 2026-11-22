package tui

import (
	"context"
	"errors"
	"io"

	tea "charm.land/bubbletea/v2"
)

// Run shows the TUI on the terminal behind in and out (on the alternate
// screen) until the user quits or ctx ends.
func Run(ctx context.Context, opt Options, in io.Reader, out io.Writer) error {
	m := New(opt)
	defer m.Close()
	p := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out))
	_, err := p.Run()
	if errors.Is(err, tea.ErrProgramKilled) && ctx.Err() != nil {
		return nil // interrupted from outside: a normal way to stop
	}
	return err
}
