package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	_ "net/http/pprof" // Пакет для профилирования
	"os"
	"runtime/pprof"
)

import "C"

// Константы для MD6
const MD6BlockSize = 64 // Размер блока (512 бит, 64 байта)

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
	precomputeSi(40 + int(math.Floor(float64(MD6BlockSize*8)/4)))
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

func generateSi(round int) uint64 {
	Sj := S0
	for j := 0; j <= round; j++ {
		// Применяем в коде:
		Sj = rotateLeft(Sj, 1) ^ (Sj & S_star)
	}
	return Sj
}

func compressF(block []byte, key string, rounds int) []byte {
	n := 89
	c := 16
	t_cycle := rounds * 16
	A := make([]uint64, 89+t_cycle)
	for i := 0; i < len(Q); i++ {
		A[i] = Q[i]
	}

	// Заполнение A значениями из ключа K
	K := make([]uint64, len(key)/8)
	for i := 0; i < len(K); i++ {
		K[i] = binary.LittleEndian.Uint64([]byte(key)[i*8 : (i+1)*8])
	}

	for i := 0; i < len(K); i++ {
		A[len(Q)+i] = K[i]
	}

	A[len(Q)+len(K)] = U
	A[len(Q)+len(K)+1] = V

	blockWords := len(block) / 8
	for i := 0; i < blockWords; i++ {
		A[len(Q)+len(K)+2+i] = binary.LittleEndian.Uint64(block[i*8 : (i+1)*8])
	}

	if blockWords < 74 {
		padding := make([]byte, (74-blockWords)*8)
		for i := 0; i < len(padding); i++ {
			padding[i] = 0x00
		}
		for i := 0; i < (74 - blockWords); i++ {
			A[len(Q)+len(K)+2+blockWords+i] = binary.LittleEndian.Uint64(padding[i*8 : (i+1)*8])
		}
	}

	Si := make([]uint64, rounds)
	for i := 0; i < rounds; i++ {
		Si[i] = generateSi(i)
	}

	for i := n; i < t_cycle; i++ {
		siIndex := (i - n) % 16
		x := SiCache[siIndex] ^ A[i-n] ^ A[i-t[0]]
		x ^= (A[i-t[1]] & A[i-t[2]]) ^ (A[i-t[3]] & A[i-t[4]])
		x ^= x >> uint(r[(i-n)%16])
		x ^= x << uint(shifts[(i-n)%16])

		A[i] = x
	}

	startIndex := t_cycle - 16
	output := make([]byte, c*8)
	for i := 0; i < c; i++ {
		value := A[startIndex+i]
		binary.LittleEndian.PutUint64(output[i*8:(i+1)*8], value)
	}

	return output
}

// Функция для обработки блоков
func buildTree(blocks [][]byte, key string, rounds int) []byte {
	// Массив для хранения хэшей блоков
	hashes := make([][]byte, len(blocks))

	// Последовательная обработка блоков
	for i, block := range blocks {
		hash := compressF(block, key, rounds)
		hashes[i] = hash // Записываем хеш в массив
	}

	// Объединение хешей в дереве
	for len(hashes) > 1 {
		var newHashes [][]byte

		// Обрабатываем все блоки попарно
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := append(hashes[i], hashes[i+1]...)
				newHash := compressF(combined, key, rounds)
				newHashes = append(newHashes, newHash)
			} else {
				// Если нечетное количество блоков, копируем последний
				newHashes = append(newHashes, hashes[i])
			}
		}

		// Переназначаем hashes на новые объединенные хеши
		hashes = newHashes
	}

	// Логирование финального хэша
	fmt.Printf("Final hash: %x\n", hashes[0])
	return hashes[0]
}

// MD6 для данных из файла
//
//export MD6FromFile
func MD6FromFile(filePath *C.char, key *C.char, outputLength C.int) *C.char {
	// Запускаем профилирование CPU перед выполнением основного кода
	startCPUProfile()

	goFilePath := C.GoString(filePath)
	goKey := C.GoString(key)
	rounds := 40 + int(math.Floor(float64(outputLength*16)/4))

	// Чтение файла
	data, err := ioutil.ReadFile(goFilePath)
	if err != nil {
		fmt.Println("Ошибка чтения файла:", err)
		stopCPUProfile() // Завершаем профилирование
		return nil
	}

	// Разбивка на блоки
	blocks := splitIntoBlocks(data, MD6BlockSize)

	// Основной хеширующий процесс
	finalHash := buildTree(blocks, goKey, rounds)

	// Обработка длины хеша
	if int(outputLength) > len(finalHash) {
		outputLength = C.int(len(finalHash))
	}
	hash := hex.EncodeToString(finalHash[:outputLength])

	// Завершаем профилирование перед возвратом
	stopCPUProfile()

	return C.CString(hash)
}

// Функция для профилирования
func startCPUProfile() {
	f, err := os.Create("cpu_profile.prof")
	if err != nil {
		log.Fatal("Ошибка при создании профиля: ", err)
	}
	pprof.StartCPUProfile(f)
	fmt.Println("Профилирование CPU начато...")
}

func stopCPUProfile() {
	pprof.StopCPUProfile()
	fmt.Println("Профилирование CPU завершено...")
}

/*
// MD6 для данных из файла
//
//export MD6FromFile
func MD6FromFile(filePath *C.char, key *C.char, outputLength C.int) *C.char {
	goFilePath := C.GoString(filePath)
	goKey := C.GoString(key)
	rounds := 40 + int(math.Floor(float64(outputLength*16)/4))
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
*/
//export MD6FromInput
func MD6FromInput(inputData *C.char, key *C.char, outputLength C.int) *C.char {
	goInputData := C.GoString(inputData)
	goKey := C.GoString(key)
	rounds := 40 + int(math.Floor(float64(outputLength*16)/4))
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
