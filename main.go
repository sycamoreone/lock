// Lock is an implementation of the github.com/kaepora/miniLock encrypted container.
// This is a simple CLI interface to decrypt minilock container.
package main

import (
	"fmt"
	"flag"
	"os"
	"log"

	"golang.org/x/crypto/ssh/terminal"
	"github.com/sycamoreone/lock/minilock"
)

var (
	ourPublic, ourSecret *[32]byte // Our own long-term keys.
)

func main() {
	log.SetFlags(log.LstdFlags | log.Llongfile)
	flag.Parse()

	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err.Error())
	}
	defer terminal.Restore(0, oldState)
	term := terminal.NewTerminal(os.Stdin, "")

	file, err := os.Open(flag.Arg(0))
	if err != nil {
		log.Fatalf("error opening file: %s\n", flag.Arg(0))
	}
	defer file.Close()

	term.SetPrompt("Email address (i.e. user@example.com, enter to quit): ")
	mailaddr, err := term.ReadLine()
	if err != nil || len(mailaddr) == 0 {
		return
	}	

	passwd, err := term.ReadPassword(fmt.Sprint("Passphrase (will not be saved to disk): "))
	if err != nil {
		term.Write([]byte("Failed to read passphrase: "+err.Error()+"\n"))
		return
	}
	
	ourPublic, ourSecret, err := minilock.DeriveKeys([]byte(passwd), []byte(mailaddr))
	if err != nil {
		log.Fatalf("error deriving key: %v\n", err)
	}
	term.Write([]byte("Your minilock ID is " + minilock.ID(ourPublic) + "\n"))

	// Check for -d and -e flags. Else print usage()

	filename, content, err := minilock.Open(file, ourPublic, ourSecret)
	if err != nil {
		log.Fatalf("error decrypting file: %v\n", err)
	}
	term.Write([]byte("Writing decrypted content to " + filename))
	file, err = os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	n, err := file.Write(content)
	if n < len(content) || err != nil {
		log.Fatalf("error writing to file: %v\n", err)
	}
}

