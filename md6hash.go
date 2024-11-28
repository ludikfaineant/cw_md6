package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/bits"
	"os"
	"sync"
)

// MD6BlockSize — размер блока MD6 (512 бит или 64 байта)
const MD6BlockSize = 64
const MD6HashSize = 32 // Длина итогового хэша (256 бит)

var (
	outputLength int
	rounds       int
	key          string
)

// MD6 вычисляет хэш с использованием параллельной обработки блоков.
func MD6(data []byte, key []byte, outputLength int, rounds int) string {

	// Разделяем данные на блоки
	blocks := splitIntoBlocks(data, MD6BlockSize)

	// Канал для сбора промежуточных хэшей
	hashResults := make(chan []byte, len(blocks))

	// Используем WaitGroup для синхронизации горутин
	var wg sync.WaitGroup

	// Параллельная обработка блоков
	for i, block := range blocks {
		wg.Add(1)
		go func(blockIndex int, blockData []byte) {
			defer wg.Done()
			// Сжимаем блок с использованием собственной функции сжатия
			hash := compressF(blockData, string(key), rounds)
			hashResults <- hash[:]
		}(i, block)
	}

	// Закрываем канал после завершения всех горутин
	go func() {
		wg.Wait()
		close(hashResults)
	}()

	// Сбор промежуточных хэшей
	var intermediateHashes []byte
	for hash := range hashResults {
		intermediateHashes = append(intermediateHashes, hash...)
	}

	// Финальная компрессия для получения корневого хэша
	finalHash := compressF(intermediateHashes, string(key), rounds)

	// Обрезаем до нужной длины
	if outputLength > len(finalHash) {
		outputLength = len(finalHash)
	}
	return hex.EncodeToString(finalHash[:outputLength])
}

// splitIntoBlocks разбивает данные на блоки заданного размера.
func splitIntoBlocks(data []byte, blockSize int) [][]byte {
	var blocks [][]byte
	for len(data) > 0 {
		if len(data) > blockSize {
			blocks = append(blocks, data[:blockSize])
			data = data[blockSize:]
		} else {
			// Дополняем последний блок до размера blockSize
			padding := make([]byte, blockSize-len(data))
			blocks = append(blocks, append(data, padding...))
			break
		}
	}
	return blocks
}

func compressF(block []byte, key string, rounds int) []byte {
	state := make([]uint64, 16)

	if len(block) < 64 {
		block = append(block, make([]byte, 64-len(block))...) // Заполнение блока нулями
	}

	for i := 0; i < len(state); i++ {
		if len(block) >= (i+1)*8 {
			state[i] = binary.LittleEndian.Uint64(block[i*8 : (i+1)*8])
		} else {
			state[i] = 0
		}
	}

	if len(key) > 0 {
		for i := 0; i < len(state); i++ {
			if len(key) >= (i+1)*8 {
				state[i] ^= binary.LittleEndian.Uint64([]byte(key)[i*8:])
			}
		}
	}

	for round := 0; round < rounds; round++ {
		for i := 0; i < len(state); i++ {
			a := state[i]
			b := state[(i+1)%16]
			c := state[(i+2)%16]
			d := state[(i+3)%16]
			state[i] = bits.RotateLeft64(a^b, int(c%64)) + (c & d)
		}
	}

	output := make([]byte, 128)
	for i := 0; i < len(state); i++ {
		binary.LittleEndian.PutUint64(output[i*8:], state[i])
	}

	return output
}

func main() {
	// Обработка параметров командной строки
	flag.IntVar(&outputLength, "outputLength", 16, "Length of the hash in bytes (e.g., 16, 32)")
	flag.IntVar(&rounds, "rounds", 80, "Number of rounds for the MD6 algorithm")
	flag.StringVar(&key, "key", "", "Key to be used for hashing")
	flag.Parse()

	// Чтение всех данных из stdin
	reader := bufio.NewReader(os.Stdin)
	var data []byte
	for {
		line, err := reader.ReadBytes('\n') // Чтение до конца строки
		data = append(data, line...)        // Добавляем строку в общий ввод

		if err == io.EOF {
			break // Прекращаем, если достигнут конец ввода
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			os.Exit(1)
		}
	}

	// Вычисляем MD6
	hash := MD6(data, []byte(key), outputLength, rounds)
	fmt.Printf("%s\n", hash) // Выводим хэш в stdout
}
