// SPDX-License-Identifier: Apache-2.0
// Independent standard age implementation for synthetic D-142 interoperability only.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

// This is public test data, including whitespace, decomposed Unicode and an embedded NUL.
const passphrase = "\tD-142 synthetic e\u0301\x00\u5bc6\n"

type vector struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Input    string `json:"input"`
	Expected string `json:"expected"`
}

func encrypt(input io.Reader, output io.Writer, lowCost bool) error {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	if lowCost {
		// Only static public fixtures use a small work factor; the interop path uses defaults.
		recipient.SetWorkFactor(4)
	}
	writer, err := age.Encrypt(output, recipient)
	if err != nil {
		return err
	}
	if _, err := io.Copy(writer, input); err != nil {
		return err
	}
	return writer.Close()
}

func vectors(output io.Writer) error {
	var all []vector
	for _, item := range []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"binary", []byte{0, 1, 2, 127, 128, 254, 255}},
		{"text", []byte("D-142 synthetic plaintext\n")},
	} {
		var ciphertext bytes.Buffer
		if err := encrypt(bytes.NewReader(item.data), &ciphertext, true); err != nil {
			return err
		}
		input, err := json.Marshal(struct {
			Passphrase string `json:"passphrase"`
			Ciphertext string `json:"ciphertext_base64"`
		}{passphrase, base64.StdEncoding.EncodeToString(ciphertext.Bytes())})
		if err != nil {
			return err
		}
		all = append(all, vector{
			ID:       "portable-age-go-1.3.2-" + item.name,
			Kind:     "crypto.portable-age.decrypt",
			Input:    string(input),
			Expected: base64.StdEncoding.EncodeToString(item.data),
		})
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(struct {
		Format  string   `json:"format"`
		Version int      `json:"version"`
		Vectors []vector `json:"vectors"`
	}{"scoplen-test-vectors", 1, all})
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("one reference operation is required")
	}
	switch os.Args[1] {
	case "encrypt":
		return encrypt(os.Stdin, os.Stdout, false)
	case "decrypt":
		identity, err := age.NewScryptIdentity(passphrase)
		if err != nil {
			return err
		}
		reader, err := age.Decrypt(os.Stdin, identity)
		if err != nil {
			return err
		}
		_, err = io.Copy(os.Stdout, reader)
		return err
	case "vectors":
		return vectors(os.Stdout)
	default:
		return fmt.Errorf("unknown reference operation")
	}
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "synthetic age reference operation failed")
		os.Exit(1)
	}
}
