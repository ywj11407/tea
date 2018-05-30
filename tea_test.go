package tea

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_findByPk(t *testing.T) {
	content := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	key := []byte{1, 2, 3, 1, 3, 1}
	en := Encrypt(content, key, 16)

	fmt.Println("encrypt content result is:", en)

	//de, _ := decrypt(en, key, 16)
	fmt.Println(Decrypt(en, key, 16))

	ke := []byte{102, 97, 0, 0, 0, 0, 0, 0, 113, 112, 111, 110, 109, 108, 107, 106}
	fmt.Println("de ret0:", byte2int(ke, 0), byte2int(ke, 4), byte2int(ke, 8), byte2int(ke, 12))
	//key := validateKey3(ke)
	//fmt.Println("de ret0:", key)
	var code = "你好11111111111111111111111111"
	var sec = "12345678"
	scode := HexEncrypt(code, sec, 16)
	fmt.Println("scontent:", scode)
	dcode, status := HexDecrypt(scode, sec, 16)
	if status == true {
		fmt.Println("dcontent:", dcode)
	} else {
		fmt.Println("decode fail")
	}
	ans, _ := hex.DecodeString(hex.EncodeToString(str2byte(code)))

	fmt.Println("ans:", byte2str(ans))
}
