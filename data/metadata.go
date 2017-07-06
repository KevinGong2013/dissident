package data

import (
	"fmt"

	"github.com/Jeffail/gabs"
	"github.com/awnumar/dissident/coffer"
	"github.com/awnumar/dissident/crypto"
	"github.com/awnumar/memguard"
)

var (
	metaObj *gabs.Container
)

// MetaSetLength sets the length field of an entry to the supplied value.
func MetaSetLength(length int64, rootIdentifier, masterKey *memguard.LockedBuffer, fileIndex uint64) {
	metaObj = gabs.New()
	metaObj.SetP(length, "length")
	MetaSaveData(rootIdentifier, masterKey, fileIndex)
}

// MetaGetLength retrieves the length of this data and returns it.
func MetaGetLength(path string, rootIdentifier, masterKey *memguard.LockedBuffer, fileIndex uint64) int64 {
	metaObj = gabs.New()

	MetaRetrieveData(rootIdentifier, masterKey, fileIndex)

	value := metaObj.Path(path).Data()
	if value == nil {
		fmt.Println("! No length field found; was importing interrupted?")
		memguard.SafeExit(1)
	}

	return int64(value.(float64))
}

// MetaSaveData saves the metadata to the database.
func MetaSaveData(rootIdentifier, masterKey *memguard.LockedBuffer, fileIndex uint64) {
	// Grab the metadata as bytes.
	data := []byte(metaObj.String())

	var chunk []byte
	for i := 0; i < len(data); i += 4095 {
		if i+4095 > len(data) {
			// Remaining data <= 4095.
			chunk = data[len(data)-(len(data)%4095):]
		} else {
			// Split into chunks of 4095 bytes and pad.
			chunk = data[i : i+4095]
		}

		// Pad the chunk to standard size.
		padded, err := crypto.Pad(chunk, 4096)
		if err != nil {
			fmt.Println(err)
			memguard.SafeExit(1)
		}

		// Save it to the database.
		coffer.Save(crypto.DeriveIdentifier(rootIdentifier, uint64(0), -int64(i)-1), crypto.Encrypt(padded, masterKey))
	}
}

// MetaRetrieveData gets the metadata from the database and returns
func MetaRetrieveData(rootIdentifier, masterKey *memguard.LockedBuffer, fileIndex uint64) {
	// Declare variable to hold all of this metadata.
	var data []byte

	for n := -1; true; n-- {
		ct := coffer.Retrieve(crypto.DeriveIdentifier(rootIdentifier, uint64(0), int64(n)))
		if ct == nil {
			// This one doesn't exist. //EOF
			break
		}

		// Decrypt this slice.
		pt, err := crypto.Decrypt(ct, masterKey)
		if err != nil {
			fmt.Println(err)
			memguard.SafeExit(1)
		}

		// Unpad this slice.
		unpadded, e := crypto.Unpad(pt)
		if e != nil {
			fmt.Println(e)
			memguard.SafeExit(1)
		}

		// Append this chunk to the metadata.
		data = append(data, unpadded...)
	}

	if len(data) == 0 {
		// No data.
		return
	}

	// Set the global metadata JSON object to this data.
	metadataObj, err := gabs.ParseJSON(data)
	if err != nil {
		fmt.Println(err)
		memguard.SafeExit(1)
	}

	// That went well. Set the global var to that object.
	metaObj = metadataObj
}

// MetaRemoveData deletes all the metadata related to an entry.
func MetaRemoveData(rootIdentifier *memguard.LockedBuffer, fileIndex uint64) {
	for n := -1; true; n-- {
		// Get the DeriveIdentifierN for this n.
		derivedMetaIdentifierN := crypto.DeriveIdentifier(rootIdentifier, uint64(0), int64(n))

		// Check if it exists.
		if coffer.Exists(derivedMetaIdentifierN) {
			coffer.Delete(derivedMetaIdentifierN)
		} else {
			break
		}
	}
}
