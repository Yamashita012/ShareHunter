package auth

import (
	"fmt"
	"golang.org/x/term"
	"os"
)

type Credentials struct{ Username, Domain, Password, Mode string }

func ReadPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}
