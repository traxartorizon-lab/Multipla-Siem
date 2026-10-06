package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const fullChunkSize = 1 << 20
const fullBackupLimit int64 = 64 << 30

var fullMagic = []byte("MSFULL01")

func fullAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("chave de recuperacao deve ter 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Each ordered chunk and the final empty marker are authenticated. Header,
// sequence and length are bound as AAD, preventing reordering and truncation.
func encryptFull(w io.Writer, r io.Reader, key []byte) error {
	aead, err := fullAEAD(key)
	if err != nil {
		return err
	}
	header := make([]byte, 16)
	copy(header, fullMagic)
	if _, err = rand.Read(header[8:]); err != nil {
		return err
	}
	if err = fullWrite(w, header); err != nil {
		return err
	}
	buf := make([]byte, fullChunkSize)
	var total int64
	for seq := uint32(0); ; seq++ {
		n, readErr := io.ReadFull(r, buf)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return readErr
		}
		total += int64(n)
		if total > fullBackupLimit {
			return errors.New("backup excede 64 GiB")
		}
		nonce := make([]byte, 12)
		copy(nonce, header[8:])
		binary.BigEndian.PutUint32(nonce[8:], seq)
		frame := make([]byte, 8)
		binary.BigEndian.PutUint32(frame, seq)
		binary.BigEndian.PutUint32(frame[4:], uint32(n))
		aad := append(append([]byte{}, header...), frame...)
		sealed := aead.Seal(nil, nonce, buf[:n], aad)
		if err = fullWrite(w, frame); err != nil {
			return err
		}
		if err = fullWrite(w, sealed); err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
	}
}

func decryptFull(w io.Writer, r io.Reader, key []byte) error {
	aead, err := fullAEAD(key)
	if err != nil {
		return err
	}
	header := make([]byte, 16)
	if _, err = io.ReadFull(r, header); err != nil || string(header[:8]) != string(fullMagic) {
		return errors.New("arquivo de backup completo invalido")
	}
	var total int64
	for seq := uint32(0); ; seq++ {
		frame := make([]byte, 8)
		if _, err = io.ReadFull(r, frame); err != nil {
			return errors.New("backup truncado")
		}
		n := binary.BigEndian.Uint32(frame[4:])
		if binary.BigEndian.Uint32(frame) != seq || n > fullChunkSize {
			return errors.New("sequencia de backup invalida")
		}
		total += int64(n)
		if total > fullBackupLimit {
			return errors.New("backup excede limite")
		}
		sealed := make([]byte, int(n)+aead.Overhead())
		if _, err = io.ReadFull(r, sealed); err != nil {
			return errors.New("backup truncado")
		}
		nonce := make([]byte, 12)
		copy(nonce, header[8:])
		binary.BigEndian.PutUint32(nonce[8:], seq)
		aad := append(append([]byte{}, header...), frame...)
		plain, err := aead.Open(nil, nonce, sealed, aad)
		if err != nil {
			return errors.New("chave incorreta ou backup adulterado")
		}
		if n == 0 {
			var extra [1]byte
			if count, e := r.Read(extra[:]); count != 0 || e != io.EOF {
				return errors.New("dados adicionais no backup")
			}
			return nil
		}
		if err = fullWrite(w, plain); err != nil {
			return err
		}
	}
}

func fullWrite(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}
