package tea

import (
	"encoding/hex"
	"fmt"
	"strings"
)

var n = 6

func byte2str(bytes []byte) string {
	return string(bytes[:])
}

func str2byte(str string) []byte {
	return []byte(str)
}

func en(v []uint32, k []uint32, rounds int) []uint32 {
	var sum uint32 = 0
	var delta uint32 = 0x9e3779b9
	var y = v[0]
	var z = v[1]
	var a = k[0]
	var b = k[1]
	var c = k[2]
	var d = k[3]
	o := make([]uint32, 2)
	for rounds > 0 {
		rounds--
		sum += delta
		y += ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b)
		z += ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d)
	}
	o[0] = y
	o[1] = z
	return o
}

//ok
func de(v []uint32, k []uint32, rounds int) []uint32 {
	var y = v[0]
	var z = v[1]
	var sum uint32 = 0
	var delta uint32 = 0x9e3779b9
	var a = k[0]
	var b = k[1]
	var c = k[2]
	var d = k[3]
	if rounds == 32 {
		sum = 0xC6EF3720
	} else {
		sum = 0xE3779B90
	}
	o := make([]uint32, 2)
	for rounds > 0 {
		rounds--
		z -= ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d)
		y -= ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b)
		sum -= delta
	}
	o[0] = y
	o[1] = z
	return o
}

//ok
func byte2int(buf []byte, offset int) uint32 {
	var sum uint32
	for i := 0; i < 4; i++ {
		sum += uint32(buf[i+offset]) << uint32(24-8*i)
	}
	return sum
}

func int2byte(integer uint32, buf []byte, offset int) {
	buf[offset] = (byte)(integer >> 24)
	buf[(offset + 1)] = (byte)(integer >> 16)
	buf[(offset + 2)] = (byte)(integer >> 8)
	buf[(offset + 3)] = (byte)(integer)
}

func flagCompare(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	flag := []byte{125, 125, 125, 125, 125, 125, 125, 125}
	for i := 0; i < 8; i++ {
		if content[i] != flag[i] {
			return 0
		}
	}
	return 1
}

func flag(orignal []byte) []byte {
	return append([]byte{125, 125, 125, 125, 125, 125, 125, 125}, orignal...)
}

func unflag(orignal []byte) []byte {
	return orignal[8:]
}

//ok
func validateKey3(key []byte) []uint32 {
	tempkey := make([]byte, 16)
	if len(key)-n+1 < 8 {
		copy(tempkey, key[n-1:])
		for i := 8; i < 16; i++ {
			tempkey[i] = (byte)(127 - n - i)
		}
		k := append([]uint32{}, byte2int(tempkey, 0), byte2int(tempkey, 4), byte2int(tempkey, 8), byte2int(tempkey, 12))
		return k
	}
	copy(tempkey, key[n-1:n-1+8])
	for i := 8; i < 16; i++ {
		tempkey[i] = (byte)(127 - n - i)
	}
	k1 := append([]uint32{}, byte2int(tempkey, 0), byte2int(tempkey, 4), byte2int(tempkey, 8), byte2int(tempkey, 12))
	return k1
}

func encry(content []byte, key []byte, rounds int) []byte {
	var resultLength = len(content)
	var mol = resultLength % 8
	if mol != 0 {
		resultLength = resultLength + 8 - mol
		for i := 0; i < 8-mol; i++ {
			content = append(content, byte(0))
		}
	}
	k := validateKey3(key)
	v := make([]uint32, 2)
	o := make([]uint32, 2)
	result := make([]byte, resultLength)
	var convertTimes = resultLength
	var next = 0
	var times = 0
	for ; times < convertTimes; times += 8 {
		next = times + 4
		v[0] = byte2int(content, times)
		v[1] = byte2int(content, next)
		o = en(v, k, rounds)
		int2byte(o[0], result, times)
		int2byte(o[1], result, next)
	}
	next = times + 4
	return flag(result)
}

func decry(scontent []byte, key []byte, rounds int) ([]byte, bool) {
	if flagCompare(scontent) == 1 {
		var content = unflag(scontent)
		if len(content)%8 != 0 {
			fmt.Println("Can't decrypt")
			return []byte{}, false
		}
		k := validateKey3(key)
		v := make([]uint32, 2)
		o := make([]uint32, 2)
		result := make([]byte, len(content))
		var convertTimes = len(content)
		var next = 0
		var times = 0
		for ; times < convertTimes; times += 8 {
			next = times + 4
			v[0] = byte2int(content, times)
			v[1] = byte2int(content, next)
			o = de(v, k, rounds)
			int2byte(o[0], result, times)
			int2byte(o[1], result, next)
		}

		convertTimes -= 8
		for times = convertTimes + 1; times < len(content); times++ {
			if result[times] == 0 {
				break
			}
		}
		res := make([]byte, times)
		copy(res, result[0:times])
		//System.arraycopy(tmp, 0, result, 0, times)
		return res, true
	}

	return []byte{}, false
}

func Encrypt(scontent string, skey string, rounds int) string {
	return strings.ToUpper(hex.EncodeToString(encry(str2byte(scontent), str2byte(skey), rounds)))
}

func Decrypt(dcontent string, skey string, rounds int) (string, bool) {
	content, err := hex.DecodeString(dcontent)
	if err != nil {
		return "", false
	}
	res, status := decry(content, str2byte(skey), rounds)
	return byte2str(res), status
}
