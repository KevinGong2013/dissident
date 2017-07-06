package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/awnumar/memguard"
)

func TestDeriveSecureValues(t *testing.T) {
	masterPassword, _ := memguard.NewFromBytes([]byte("yellow submarine"), false)
	identifier, _ := memguard.NewFromBytes([]byte("yellow submarine"), false)

	masterKey, rootIdentifier := DeriveSecureValues(masterPassword, identifier, map[string]int{"N": 18, "r": 16, "p": 1})

	actualMasterKey, _ := base64.StdEncoding.DecodeString("IQ0m0/Z7Oy/rvm67Pi0nj2Zk8N0u0Ba+t/uyhPVxTF8=")
	actualRootIdentifier, _ := base64.StdEncoding.DecodeString("FIRp7dJQ2RvA7jsQX1DFWxxit6t9ERMyCSloA8iRmU4=")

	if !bytes.Equal(masterKey.Buffer, actualMasterKey) {
		t.Error("Derived master key != actual value")
	}

	if !bytes.Equal(rootIdentifier.Buffer, actualRootIdentifier) {
		t.Error("Derived root identifier != actual value")
	}
}

func TestDeriveIdentifierN(t *testing.T) {
	rootIdentifierBytes, _ := base64.StdEncoding.DecodeString("FIRp7dJQ2RvA7jsQX1DFWxxit6t9ERMyCSloA8iRmU4=")
	rootIdentifier, _ := memguard.NewFromBytes(rootIdentifierBytes, false)

	values := []string{
		"1ThoAwd+zdKmU8I/Gu3GBz8Q/dWBWR1gVbD02/u+/xs=",
		"3DwIOsXt6lVJnOPbWfLoYwavGpzEEYP2NQUDfso4IVc=",
		"LtxOgR+bjyMyPgHg9H4GCTcB0A3stmYd/abYRGEFxvM=",
		"4bki0lPfi96iRL4gsE3FX3gsOsj0RBbJI/Jv9oK3kjg=",
		"BV+woYOCEceHRjMMJhPwzeBqA5xVd6puSJr/VMHixvg=",
		"+AjyNTn4og8YR5GEn8V4MFmUsL15Mv5rrOVe3wrHvFY=",
		"9f2zXHp+rYGVVwhkWvtyti6D7tLbCBfwoTn9yfK/i58=",
		"/6kG4wK84IXKRxIgX7rvfMXYexevliK1AcJrHg8P8O4=",
		"Q2bgn06fopp40oiUKx5Bs9w90K8BwWL9EsdMXBEiS7Q="}

	index := 0

	for i := 0; i < 3; i++ {
		for j := 0; j > -3; j-- {
			derived := DeriveIdentifier(rootIdentifier, uint64(i), int64(j))
			actual, _ := base64.StdEncoding.DecodeString(values[index])

			if !bytes.Equal(derived, actual) {
				t.Error("derivedIdentifier != actual")
			}

			index++
		}
	}
}
