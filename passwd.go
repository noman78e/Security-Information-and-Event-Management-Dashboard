package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"homesiem/auth"
	"homesiem/store"
)

var stdin = bufio.NewReader(os.Stdin)

// readSecret reads a line without showing it, where the system allows it.
func readSecret(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	hidden := false
	if runtime.GOOS != "windows" {
		off := exec.Command("stty", "-echo")
		off.Stdin = os.Stdin
		hidden = off.Run() == nil
	}
	line, _ := stdin.ReadString('\n')
	if hidden {
		on := exec.Command("stty", "echo")
		on.Stdin = os.Stdin
		on.Run()
		fmt.Fprintln(os.Stderr)
	}
	return strings.TrimRight(line, "\r\n")
}

// runPasswd is "homesiem passwd": it sets a new dashboard password without
// asking for the old one. It needs access to the database file, so it is
// the way back in if the password is forgotten.
func runPasswd(args []string) {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	dbPath := fs.String("db", "homesiem.db", "path to the HomeSIEM database")
	fs.Parse(args)

	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open the database %s: %v\n", *dbPath, err)
		os.Exit(1)
	}
	defer st.Close()

	if runtime.GOOS == "windows" {
		fmt.Fprintln(os.Stderr, "(On Windows what you type is visible.)")
	}
	pw := readSecret("New dashboard password (at least 10 characters): ")
	if readSecret("Type it again: ") != pw {
		fmt.Fprintln(os.Stderr, "The two entries are different. Nothing was changed.")
		os.Exit(1)
	}
	if err := auth.Reset(st, pw); err != nil {
		fmt.Fprintf(os.Stderr, "Nothing was changed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("The dashboard password was changed.")
	fmt.Println("Restart HomeSIEM to end any sign-ins that are still open.")
}
