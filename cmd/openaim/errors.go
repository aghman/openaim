package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// cliError is a failure with its exit code and a stable kind for --json.
type cliError struct {
	code int
	kind string // e.g. "not_found"; the "code" field of a JSON error
	msg  string
	hint string // a second line for humans, or ""
}

func (e *cliError) Error() string { return e.msg }

func usageErrorf(format string, a ...any) error {
	return &cliError{code: exitUsage, kind: "usage", msg: fmt.Sprintf(format, a...)}
}

// errHelpShown means -h printed the command's help: exit 0, print nothing.
var errHelpShown = errors.New("help shown")

// fail prints err (if any) and returns the exit code.
func (cl *cli) fail(err error) int {
	if err == nil || errors.Is(err, errHelpShown) {
		return exitOK
	}
	var ce *cliError
	if !errors.As(err, &ce) {
		ce = &cliError{code: exitError, kind: "error", msg: err.Error()}
	}
	prefix := "openaim"
	if cl.cmd != "" {
		prefix += " " + cl.cmd
	}
	if ce.code == exitUsage && ce.hint == "" {
		if cl.cmd != "" {
			ce.hint = fmt.Sprintf(`run "openaim help %s" for usage`, cl.cmd)
		} else {
			ce.hint = `run "openaim help" for usage`
		}
	}
	if cl.g.json {
		obj := map[string]any{"error": ce.msg, "code": ce.kind, "exit_code": ce.code}
		if b, err := marshalJSON(obj); err == nil {
			cl.e.stderr.Write(b)
			return ce.code
		}
	}
	fmt.Fprintf(cl.e.stderr, "%s: %s\n", prefix, clean(ce.msg))
	if ce.hint != "" {
		fmt.Fprintf(cl.e.stderr, "  (%s)\n", clean(ce.hint))
	}
	return ce.code
}

// rpcErr turns a gRPC error into a cliError with the right exit code.
func (cl *cli) rpcErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return &cliError{code: exitError, kind: "canceled", msg: "canceled"}
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	msg := strings.TrimPrefix(st.Message(), "daemon: ")
	switch st.Code() {
	case codes.Unavailable:
		return cl.notRunning(fmt.Sprintf("nothing answers on %s", cl.sock))
	case codes.NotFound:
		return &cliError{code: exitNotFound, kind: "not_found", msg: msg, hint: `list buddies with "openaim buddies"`}
	case codes.AlreadyExists:
		return &cliError{code: exitExists, kind: "already_exists", msg: msg}
	case codes.InvalidArgument:
		return &cliError{code: exitError, kind: "invalid_argument", msg: msg}
	case codes.FailedPrecondition:
		return &cliError{code: exitError, kind: "failed_precondition", msg: msg}
	case codes.DeadlineExceeded:
		return &cliError{code: exitError, kind: "timeout",
			msg: fmt.Sprintf("openaimd did not answer within %v", cl.g.timeout), hint: "raise --timeout"}
	case codes.Canceled:
		return &cliError{code: exitError, kind: "canceled", msg: "canceled"}
	}
	return &cliError{code: exitError, kind: strings.ToLower(st.Code().String()), msg: msg}
}
