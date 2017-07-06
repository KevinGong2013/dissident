package crypto

import (
	"encoding/binary"
	"fmt"
	"runtime/debug"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/scrypt"
)

// DeriveSecureValues derives and returns a masterKey and rootIdentifier.
func DeriveSecureValues(masterPassword, identifier *memguard.LockedBuffer, costFactor map[string]int) (*memguard.LockedBuffer, *memguard.LockedBuffer) {
	// Allocate and protect memory for the concatenated values, and append the values to it.
	concatenatedValues, err := memguard.Concatenate(masterPassword, identifier)
	if err != nil {
		fmt.Println(err)
		memguard.SafeExit(1)
	}
	defer concatenatedValues.Destroy()

	// Derive the rootKey and then protect it.
	rootKeySlice, _ := scrypt.Key(
		concatenatedValues.Buffer, // Input data.
		[]byte(""),                // Salt.
		1<<uint(costFactor["N"]),  // Scrypt parameter N.
		costFactor["r"],           // Scrypt parameter r.
		costFactor["p"],           // Scrypt parameter p.
		64)                        // Output hash length.
	rootKey, _ := memguard.NewFromBytes(rootKeySlice, false)
	defer rootKey.Destroy()

	// Force the Go GC to do its job.
	debug.FreeOSMemory()

	// Get the respective values.
	masterKey, rootIdentifier, err := memguard.Split(rootKey, 32)
	if err != nil {
		fmt.Println(err)
		memguard.SafeExit(1)
	}

	// Slice and return respective values.
	return masterKey, rootIdentifier
}

// DeriveIdentifier derives a value for derivedIdentifier for given file and chunk indexes.
func DeriveIdentifier(rootIdentifier *memguard.LockedBuffer, fileIndex uint64, chunkIndex int64) []byte {
	// Convert values to binary.
	fileIndexBytes := make([]byte, 10)
	binary.PutUvarint(fileIndexBytes, fileIndex)

	chunkIndexBytes := make([]byte, 10)
	binary.PutVarint(chunkIndexBytes, chunkIndex)

	// Append the uint64 to the root identifier.
	hashArg, _ := memguard.New(52, false)
	hashArg.Copy(rootIdentifier.Buffer)
	hashArg.CopyAt(fileIndexBytes, 32)
	hashArg.CopyAt(chunkIndexBytes, 42)
	defer hashArg.Destroy()

	// Derive derivedIdentifier.
	derivedIdentifier := blake2b.Sum256(hashArg.Buffer)

	// Return as slice instead of array.
	return derivedIdentifier[:]
}
