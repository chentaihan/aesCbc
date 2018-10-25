package aesCbc

import (
	"unsafe"
	"bytes"
)

const (
	BLOCK_SIZE = 32
)

var keySizes = []int{16, 24, 32}

type cbcBuffer struct {
	previous_ciphertext []uint32
	previous_cipher     []uint32
	blocksize           int
}

type RI struct {
	Nk   int
	Nb   int
	Nr   int
	fi   [24]byte
	ri   [24]byte
	fkey [120]uint32
	rkey [120]uint32
}

type AesCipher struct {
	/* Holds the algorithm's internal key */
	rinst  *RI
	buffer *cbcBuffer /* holds the mode's internal buffers */

	/* holds the key */
	key []byte

	/* These were included to speed up encryption/decryption proccess, so
	 * there is not need for resolving symbols every time.
	 */
	blockSize int
}

func NewAesCipher(key, iv []byte) *AesCipher {
	td := mcryptOpen()
	mcryptGenericInit(td, key, iv)
	return td
}

func (aesCipher *AesCipher) Encrypt(origData []byte) []byte {
	dataSize := ((len(origData)-1 )/aesCipher.blockSize + 1) * aesCipher.blockSize
	newData := make([]byte, dataSize)
	copy(newData, origData)
	return mcrypt(aesCipher.buffer, newData, aesCipher.blockSize, aesCipher.rinst)
}

func (aesCipher *AesCipher) Decrypt(origData []byte) []byte {
	return mdecrypt(aesCipher.buffer, origData, aesCipher.blockSize, aesCipher.rinst)
}

func (aesCipher *AesCipher) BlockSize() int {
	return aesCipher.blockSize
}

//获取加密key长度
func getKeySize(size int) int {
	for _, val := range keySizes {
		if size <= val {
			return val
		}
	}
	return 32
}

func getBlockSize() int {
	return BLOCK_SIZE
}

func mcryptOpen() *AesCipher {
	td := &AesCipher{}
	td.blockSize = getBlockSize()
	td.buffer = &cbcBuffer{}
	td.rinst = &RI{}
	return td
}

//初始化秘钥
func mcryptGenericInit(td *AesCipher, key, iv []byte) int {
	keySize := len(key)
	if keySize == 0 || keySize > td.blockSize {
		return -1
	}
	if len(iv) < td.blockSize {
		newIv := make([]byte, td.blockSize)
		copy(newIv, iv)
		iv = newIv
	} else {
		iv = iv[:td.blockSize]
	}
	td.key = make([]byte, td.blockSize)
	copy(td.key, key)
	initMcrypt(td.buffer, iv, td.blockSize)
	mcryptSetKey(td.rinst, td.key, getKeySize(keySize))
	return 0
}

func initMcrypt(buf *cbcBuffer, iv []byte, size int) {
	buf.blocksize = size
	buf.previous_ciphertext = make([]uint32, size/4)
	buf.previous_cipher = make([]uint32, size/4)
	index := 0
	for i := 0; i < size; i += 4 {
		buf.previous_ciphertext[index] = pack(iv[i:])
		index++
	}
}

//cbc加密
func mcrypt(buf *cbcBuffer, plaintext []byte, blocksize int, rinst *RI) []byte {
	var plain []uint32
	intSize := 4
	txtLen := len(plaintext)
	fplain := *((*[]uint32)(unsafe.Pointer(&plaintext)))
	onceLen := blocksize / intSize //8
	for j := 0; j < txtLen/blocksize; j++ {
		plain = fplain[j*blocksize/intSize:]
		for i := 0; i < onceLen; i++ {
			plain[i] ^= buf.previous_ciphertext[i]
		}
		//每次加密32字节
		mcryptEncrypt(rinst, *((*[]byte)(unsafe.Pointer(&plain))))
		/* Copy the ciphertext to prev_ciphertext */
		copy(buf.previous_ciphertext, plain)
	}
	return plaintext
}

//cbc解密
func mdecrypt(buf *cbcBuffer, ciphertext []byte, blocksize int, rinst *RI) []byte {
	var cipher []uint32
	fcipher := *((*[]uint32)(unsafe.Pointer(&ciphertext)))
	txtLen := len(ciphertext)
	intSize := 4
	for j := 0; j < txtLen/blocksize; j++ {
		cipher = fcipher[j*blocksize/intSize:]
		copy(buf.previous_cipher, cipher)
		mcryptDecrypt(rinst, *((*[]byte)(unsafe.Pointer(&cipher))))
		for i := 0; i < blocksize/intSize; i++ {
			cipher[i] ^= buf.previous_ciphertext[i]
		}
		/* Copy the ciphertext to prev_cipher */
		copy(buf.previous_ciphertext, buf.previous_cipher)
	}
	return bytes.Trim(ciphertext, "\x00")
}
