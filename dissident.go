package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/awnumar/dissident/coffer"
	"github.com/awnumar/dissident/crypto"
	"github.com/awnumar/dissident/data"
	"github.com/awnumar/dissident/stdin"
	"github.com/awnumar/memguard"
	"github.com/cheggaaa/pb"
)

var (
	// The default cost factor for key deriviation.
	scryptCost = map[string]int{"N": 18, "r": 16, "p": 1}

	// Store a global reference to the master password.
	masterPassword *memguard.LockedBuffer
)

func main() {
	// Setup the secret store.
	err := coffer.Setup()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer coffer.Close()

	// Cleanup memory when exiting.
	memguard.CatchInterrupt(func() {})
	defer memguard.DestroyAll()

	// Launch CLI.
	err = cli()
	if err != nil {
		fmt.Println(err)
	}
}

func cli() error {
	help := `import [path] - Import a new file to the database.
export [path] - Retrieve data from the database and export to a file.
peak          - Grab data from the database and print it to the screen.
remove        - Remove some previously stored data from the database.
decoys        - Add a variable amount of random decoy data.
exit          - Exit the program.`

	masterPassword = stdin.GetMasterPassword()
	fmt.Println("") // For formatting.

	for {
		cmd := strings.Split(strings.TrimSpace(stdin.Standard("$ ")), " ")

		switch cmd[0] {
		case "import":
			if len(cmd) < 2 {
				fmt.Println("! Missing argument: path")
			} else {
				importFromDisk(cmd[1])
			}
		case "export":
			if len(cmd) < 2 {
				fmt.Println("! Missing argument: path")
			} else {
				exportToDisk(cmd[1])
			}
		case "peak":
			peak()
		case "remove":
			remove()
		case "decoys":
			decoys()
		case "exit":
			return nil
		default:
			fmt.Println(help)
		}
	}
}

func importFromDisk(path string) {
	// Handle the file.
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("! %s does not exist\n", path)
		} else {
			fmt.Println(err)
		}
		return
	}

	// Ascertain the list of targets to import.
	var targets []string
	if info.IsDir() {
		visitFile := func(fp string, fo os.FileInfo, e error) error {
			if !fo.IsDir() {
				targets = append(targets, fp)
			}
			return nil
		}
		filepath.Walk(path, visitFile)
	}

	// Prompt the user for the identifier.
	identifier := stdin.Secure("- Secure identifier: ")
	defer identifier.Destroy()

	// Derive the secure values for this "branch".
	fmt.Println("+ Generating root key...")
	masterKey, rootIdentifier := crypto.DeriveSecureValues(masterPassword, identifier, scryptCost)
	defer masterKey.Destroy()
	defer rootIdentifier.Destroy()

	var n uint64
	for n = 0; n < uint64(len(targets)); n++ {
		// Check if it exists already.
		derivedIdentifier := crypto.DeriveIdentifier(rootIdentifier, n, int64(0))
		if coffer.Exists(derivedIdentifier) {
			fmt.Println("! Cannot overwrite existing entry")
			return
		}

		// Import this entry from disk.
		data.ImportData(targets[n], n, rootIdentifier, masterKey)
	}
}

func exportToDisk(path string) {
	// Prompt the user for the identifier.
	identifier := stdin.Secure("- Secure identifier: ")
	defer identifier.Destroy()

	// Derive the secure values for this "branch".
	fmt.Println("+ Generating root key...")
	masterKey, rootIdentifier := crypto.DeriveSecureValues(masterPassword, identifier, scryptCost)
	defer masterKey.Destroy()
	defer rootIdentifier.Destroy()

	// Check if this entry exists.
	derivedIdentifierN := crypto.DeriveIdentifier(rootIdentifier, uint64(0), int64(0))
	if !coffer.Exists(derivedIdentifierN) {
		fmt.Println("! This entry does not exist")
		return
	}

	// Export the entry.
	data.ExportData(path, uint64(0), rootIdentifier, masterKey)
}

func peak() {
	// Prompt the user for the identifier.
	identifier := stdin.Secure("- Secure identifier: ")

	// Derive the secure values for this "branch".
	fmt.Println("+ Generating root key...")
	masterKey, rootIdentifier := crypto.DeriveSecureValues(masterPassword, identifier, scryptCost)

	// Check if this entry exists.
	derivedIdentifierN := crypto.DeriveIdentifier(rootIdentifier, uint64(0), int64(0))
	if !coffer.Exists(derivedIdentifierN) {
		fmt.Println("! This entry does not exist")
		return
	}

	// It exists, proceed to get data.
	data.ViewData(uint64(0), rootIdentifier, masterKey)
}

func remove() {
	// Prompt the user for the identifier.
	identifier := stdin.Secure("- Secure identifier: ")

	// Derive the secure values for this "branch".
	fmt.Println("+ Generating root key...")
	masterKey, rootIdentifier := crypto.DeriveSecureValues(masterPassword, identifier, scryptCost)

	// Check if this entry exists.
	derivedIdentifierN := crypto.DeriveIdentifier(rootIdentifier, uint64(0), int64(0))
	if !coffer.Exists(derivedIdentifierN) {
		fmt.Println("! There is nothing here to remove")
		return
	}

	// Remove the data.
	data.RemoveData(uint64(0), rootIdentifier, masterKey)
}

func decoys() {
	var numberOfDecoys int
	var err error

	// Print some help information.
	fmt.Println(`
:: For deniable encryption, use this feature in conjunction with some fake data manually-added
   under a different master-password. Then if you are ever forced to hand over your keys,
   simply give up the fake data and claim that the rest of the entries in the database are decoys.

:: You do not necessarily have to make use of this feature. Rather, simply the fact that
   it exists allows you to claim that some or all of the entries in the database are decoys.
`)

	// Get the number of decoys to add as an int.
	for {
		numberOfDecoys, err = strconv.Atoi(stdin.Standard("How many decoys do you want to add? "))
		if err == nil {
			break
		}
		fmt.Println("! Input must be an integer")
	}

	// Create and configure the progress bar object.
	bar := pb.New64(int64(numberOfDecoys)).Prefix("+ Adding ")
	bar.ShowSpeed = true
	bar.SetUnits(pb.U_NO)
	bar.Start()

	for i := 0; i < numberOfDecoys; i++ {
		// Generate the decoy.
		identifier, ciphertext := crypto.GenDecoy()

		// Save to the database.
		coffer.Save(identifier, ciphertext)

		// Increment progress bar.
		bar.Increment()
	}
	bar.FinishPrint(fmt.Sprintf("+ Added %d decoys.", numberOfDecoys))
}
