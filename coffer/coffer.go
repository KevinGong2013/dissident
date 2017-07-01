package coffer

import (
	"os"
	"os/user"

	"github.com/awnumar/badger"
)

var (
	// Coffer is a pointer to the database object.
	Coffer *badger.KV
)

// Setup sets up the environment.
func Setup() error {
	// Ascertain the path to the user's home
	// directory and set the working directory.
	user, err := user.Current()
	if err != nil {
		return err
	}
	wDir := user.HomeDir + "/dissident"

	// Check if we've done this before.
	if _, err = os.Stat(wDir); err != nil {
		// Apparently we haven't.

		// Create a directory to store our stuff in.
		err = os.Mkdir(wDir, 0700)
		if err != nil {
			return err
		}
	}

	// Configure badger.
	opt := badger.DefaultOptions
	opt.Dir = wDir
	opt.ValueDir = wDir

	// Get the KV object.
	Coffer, err = badger.NewKV(&opt)
	if err != nil {
		return err
	}

	return nil
}

// Exists checks if an entry exists and returns true or false.
func Exists(identifier []byte) (exists bool, err error) {
	exists, err = Coffer.Exists(identifier)
	if err != nil {
		return false, err
	}
	return
}

// Save saves a secret to the database.
func Save(identifier, ciphertext []byte) error {
	return Coffer.Set(identifier, ciphertext)
}

// Retrieve retrieves a secret from the database.
func Retrieve(identifier []byte) ([]byte, error) {
	var item badger.KVItem
	if err := Coffer.Get(identifier, &item); err != nil {
		return nil, err
	}

	return item.Value(), nil
}

// Delete deletes an entry from the database.
func Delete(identifier []byte) error {
	return Coffer.Delete(identifier)
}

// Close closes the database object.
func Close() error {
	return Coffer.Close()
}
