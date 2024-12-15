package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	_ "net/http/pprof" // Пакет для профилирования
	"sync"
)

import "C"

// Константы для MD6
const MD6BlockSize = 512

// Константы для MD6
var (
	// Значения для ri−n (сдвиги для каждого раунда)
	r = [16]int{10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12}

	// Значения для `i−n` (сдвиги для каждого раунда)
	shifts = [16]int{11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9}

	// Константы для t0, t1, t2, t3, t4 (индексы)
	t = [5]int{17, 18, 21, 31, 67}

	// Константа Q (15 слов)
	Q = []uint64{
		0x7311c2812425cfa0, 0x6432286434aac8e7, 0xb60450e9ef68b7c1, 0xe8fb23908d9f06f1,
		0xdd2e76cba691e5bf, 0x0cd0d63b2c30bc41, 0x1f8ccf6823058f8a, 0x54e5ed5b88e3775d,
		0x4ad12aae0a6d6031, 0x3e7f16bb88222e0d, 0x8af8671d3fb50c2c, 0x995ad1178bd25c31,
		0xc878c1dd04c4b633, 0x3b72066c7a1552ac, 0x0d6f3522631effcb,
	}

	// Ключ K (передается как аргумент)
)

// Уникальный ID U (1 слово)
var U = uint64(0x1234567890abcdef)

// Контрольное слово V (1 слово)
var V = uint64(0xabcdef1234567890)

// Маска S*
var S_star = uint64(0x7311c2812425cfa0)

// Начальное значение S0
var S0 = uint64(0x0123456789abcdef)

// Глобальный массив для хранения предвычисленных значений Si
var SiCache []uint64

// Функция для предвычисления всех значений Si для заданного количества раундов
func precomputeSi(rounds int) {
	SiCache = make([]uint64, rounds+1)
	Sj := S0
	for round := 0; round <= rounds; round++ {
		SiCache[round] = Sj
		Sj = rotateLeft(Sj, 1) ^ (Sj & S_star)
	}
}

// Функция разбивки на блоки с дополнительным логированием
func splitIntoBlocks(data []byte, blockSize int) [][]byte {
	precomputeSi(40 + int(math.Floor(float64(32*16)/4)))
	length := len(data)
	paddingSize := blockSize - (length % blockSize)
	if paddingSize < 8 {
		paddingSize += blockSize
	}
	padding := make([]byte, paddingSize-8)
	padding[0] = 0x80
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, uint64(length*8))
	data = append(data, padding...)
	data = append(data, lenBytes...)

	var blocks [][]byte
	for len(data) > 0 {
		blocks = append(blocks, data[:blockSize])
		data = data[blockSize:]
	}

	return blocks
}

func rotateLeft(value uint64, shift uint) uint64 {
	return (value << shift) | (value >> (64 - shift))
}

// Преобразование ключа в 8 слов (64 байта), если ключ короче, добавляем паддинг
func prepareKey(key []byte) []uint64 {
	// Если ключ меньше 64 байт (8 слов), добавляем паддинг
	if len(key) < 64 {
		paddedKey := append(key, make([]byte, 64-len(key))...) // Паддинг нулями
		key = paddedKey
	}

	// Разбиваем на 8 слов (64 бита)
	K := make([]uint64, 8)
	for i := 0; i < 8; i++ {
		K[i] = binary.LittleEndian.Uint64(key[i*8 : (i+1)*8])
	}

	return K
}

func compressF(block []byte, key string, rounds int) []byte {
	n := 89                // Количество фиксированных слов
	c := 16                // Размер блока вывода
	t_cycle := rounds * 16 // Количество циклов

	// Массив A для хранения всех данных: Q, K, U, V и блок
	A := make([]uint64, 89+t_cycle)

	// 1. Заполнение первых 89 элементов массива A значениями из Q
	copy(A[:len(Q)], Q)

	// 2. Заполнение A значениями из ключа K
	keyBytes := []byte(key)
	K := prepareKey(keyBytes) // Преобразуем байты в 8 слов (64 байта)
	copy(A[len(Q):len(Q)+len(K)], K)

	// 3. Заполнение значениями U и V
	A[len(Q)+len(K)] = U
	A[len(Q)+len(K)+1] = V

	// 4. Заполнение A значениями из блока
	blockWords := len(block) / 8
	for i := 0; i < blockWords; i++ {
		A[len(Q)+len(K)+2+i] = binary.LittleEndian.Uint64(block[i*8 : (i+1)*8])
	}

	// 5. Добавление паддинга, если блок меньше 74 слов
	if blockWords < 74 {
		padding := make([]uint64, 74-blockWords) // Создаем массив паддинга
		// Паддинг заполняем нулями (по умолчанию)
		copy(A[len(Q)+len(K)+2+blockWords:], padding) // Копируем паддинг в A
	}

	// 6. Основной цикл вычислений
	for i := n; i < t_cycle; i++ {
		siIndex := (i - n) % 16
		x := (SiCache[siIndex] ^ A[i-n] ^ A[i-t[0]]) ^ (A[i-t[1]] & A[i-t[2]]) ^ (A[i-t[3]] & A[i-t[4]])
		x ^= x >> uint(r[(i-n)%16])
		x ^= x << uint(shifts[(i-n)%16])

		A[i] = x
	}

	// 7. Подготовка вывода
	startIndex := t_cycle - 16
	output := make([]byte, c*8)
	for i := 0; i < c; i++ {
		value := A[startIndex+i]
		binary.LittleEndian.PutUint64(output[i*8:(i+1)*8], value)
	}

	return output
}

func buildTree(blocks [][]byte, key string, rounds int) []byte {
	hashes := make([][]byte, len(blocks))
	var wg sync.WaitGroup

	// Параллельная обработка блоков
	for i, block := range blocks {
		wg.Add(1)
		go func(i int, block []byte) {
			defer wg.Done()
			hashes[i] = compressF(block, key, rounds) // Прямое назначение в массив по индексу
		}(i, block)
	}

	wg.Wait() // Ждём завершения всех горутин

	// Объединение хэшей
	for len(hashes) > 1 {
		// Новый срез для хранения объединённых хэшей
		newHashes := make([][]byte, (len(hashes)+1)/2)

		var subWG sync.WaitGroup
		for i := 0; i < len(hashes); i += 2 {
			subWG.Add(1)
			go func(i int) {
				defer subWG.Done()

				// Объединяем текущий и следующий блоки
				var combined []byte
				if i+1 < len(hashes) {
					combined = append(hashes[i], hashes[i+1]...)
				} else {
					combined = hashes[i] // Последний блок без пары
				}

				// Хешируем объединённый блок
				newHashes[i/2] = compressF(combined, key, rounds)
			}(i)
		}

		subWG.Wait() // Ждём завершения всех горутин

		// Переходим на новый уровень
		hashes = newHashes
	}

	return hashes[0]
}

// MD6 для данных из файла
//
//export MD6FromFile
func MD6FromFile(filePath *C.char, key *C.char, outputLength C.int) *C.char {
	goFilePath := C.GoString(filePath)
	goKey := C.GoString(key)
	rounds := 40 + int(math.Floor(float64(32*16)/4))
	data, err := ioutil.ReadFile(goFilePath)
	if err != nil {
		fmt.Println("Ошибка чтения файла:", err)
		return nil
	}

	blocks := splitIntoBlocks(data, MD6BlockSize)

	finalHash := buildTree(blocks, goKey, rounds)

	if int(outputLength) > len(finalHash) {
		outputLength = C.int(len(finalHash))
	}
	hash := hex.EncodeToString(finalHash[:outputLength])
	return C.CString(hash)
}

//export MD6FromInput
func MD6FromInput(inputData *C.char, key *C.char, outputLength C.int) *C.char {
	goInputData := C.GoString(inputData)
	goKey := C.GoString(key)
	rounds := 40 + int(math.Floor(float64(32*16)/4))
	data := []byte(goInputData)
	blocks := splitIntoBlocks(data, MD6BlockSize)

	finalHash := buildTree(blocks, goKey, rounds)

	if int(outputLength) > len(finalHash) {
		outputLength = C.int(len(finalHash))
	}
	hash := hex.EncodeToString(finalHash[:outputLength])
	return C.CString(hash)
}

func main() {}
