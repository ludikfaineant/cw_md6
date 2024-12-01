package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"
	"os"
)

// Константы
const MD6BlockSize = 64 // Размер блока 512 бит (64 байта)
const MD6HashSize = 32  // Размер хэша 256 бит

// Разбивает данные на блоки фиксированного размера с добавлением padding и длины сообщения
func splitIntoBlocks(data []byte, blockSize int) [][]byte {
	length := len(data)
	paddingSize := blockSize - (length % blockSize)
	if paddingSize < 8 {
		paddingSize += blockSize
	}

	padding := make([]byte, paddingSize-8) // Padding 0x80 и нули
	padding[0] = 0x80

	// Добавляем длину данных (64-битное целое в битах)
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, uint64(length*8)) // длина в битах

	// Объединяем данные, padding и длину
	data = append(data, padding...)
	data = append(data, lenBytes...)

	// Разбиваем на блоки
	var blocks [][]byte
	for len(data) > 0 {
		blocks = append(blocks, data[:blockSize])
		data = data[blockSize:]
	}
	return blocks
}

// Функция сжатия для блока данных
func compressF(block []byte, key string, rounds int) []byte {
	state := make([]uint64, 16)
	if len(block) < 64 {
		block = append(block, make([]byte, 64-len(block))...)
	}

	// Загружаем блок в начальное состояние
	for i := 0; i < len(state); i++ {
		if len(block) >= (i+1)*8 {
			state[i] = binary.LittleEndian.Uint64(block[i*8 : (i+1)*8])
		} else {
			state[i] = 0
		}
	}

	// Если ключ не пустой, добавляем его
	if len(key) > 0 {
		for i := 0; i < len(state); i++ {
			if len(key) >= (i+1)*8 {
				state[i] ^= binary.LittleEndian.Uint64([]byte(key)[i*8:])
			}
		}
	}

	// Раунды сжатия
	for round := 0; round < rounds; round++ {
		temp := make([]uint64, 16)
		for i := 0; i < len(state); i++ {
			a := state[i]
			b := state[(i+1)%16]
			c := state[(i+2)%16]
			d := state[(i+3)%16]

			// Более сложные нелинейные операции
			temp[i] = bits.RotateLeft64(a^b, int(c%64)) +
				(c ^ d) ^
				(bits.RotateLeft64(d, int(b%64)))
		}
		// Дополнительное перемешивание
		mixState(temp)
		copy(state, temp)
	}

	// Формируем выходное состояние
	output := make([]byte, 128)
	for i := 0; i < len(state); i++ {
		binary.LittleEndian.PutUint64(output[i*8:], state[i])
	}

	return output[:MD6HashSize] // Ограничиваем результат до 256 бит
}
func mixState(state []uint64) {
	for i := range state {
		state[i] ^= bits.RotateLeft64(state[(i+1)%16], int(state[(i+2)%16]%64))
	}
}

func mixBytes(data []byte) []byte {
	for i := 0; i < len(data); i++ {
		data[i] ^= byte((i * 31) % 256)
	}
	return data
}

// Построение дерева сжатия
func buildTree(blocks [][]byte, key string, rounds int) []byte {
	hashes := make([][]byte, len(blocks))
	for i, block := range blocks {
		hashes[i] = compressF(block, key, rounds)
	}

	for len(hashes) > 1 {
		var newHashes [][]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := append(hashes[i], hashes[i+1]...)
				mixedCombined := mixBytes(combined) // Дополнительное перемешивание
				newHashes = append(newHashes, compressF(mixedCombined, key, rounds))
			} else {
				newHashes = append(newHashes, hashes[i])
			}
		}
		hashes = newHashes
	}
	return hashes[0]
}

// MD6 для данных из файла
//
//export MD6FromFile
func MD6FromFile(filePath *C.char, key *C.char, outputLength C.int, rounds C.int) *C.char {
	goKey := C.GoString(key)
	goFilePath := C.GoString(filePath)

	// Читаем данные из файла
	file, err := os.Open(goFilePath)
	if err != nil {
		fmt.Println("Ошибка открытия файла:", err)
		os.Exit(1)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Ошибка чтения файла:", err)
		os.Exit(1)
	}

	// Разбиваем данные на блоки
	blocks := splitIntoBlocks(data, MD6BlockSize)

	// Строим дерево сжатия
	finalHash := buildTree(blocks, goKey, int(rounds))

	// Урезаем финальный хэш до нужной длины
	if int(outputLength) > len(finalHash) {
		outputLength = C.int(len(finalHash))
	}
	hash := hex.EncodeToString(finalHash[:outputLength])
	return C.CString(hash)
}

// MD6 для данных из строки
//
//export MD6FromInput
func MD6FromInput(inputData *C.char, key *C.char, outputLength C.int, rounds C.int) *C.char {
	goKey := C.GoString(key)
	goInputData := C.GoString(inputData)

	// Преобразуем строку в байты и разбиваем на блоки
	data := []byte(goInputData)
	blocks := splitIntoBlocks(data, MD6BlockSize)

	// Строим дерево сжатия
	finalHash := buildTree(blocks, goKey, int(rounds))

	// Урезаем финальный хэш до нужной длины
	if int(outputLength) > len(finalHash) {
		outputLength = C.int(len(finalHash))
	}
	hash := hex.EncodeToString(finalHash[:outputLength])
	return C.CString(hash)
}

func main() {}
