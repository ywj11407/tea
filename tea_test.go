package tea

import (
	"fmt"
	"testing"
)

func Test_findByPk(t *testing.T) {
	var code = "123456asfdasfasfdasfdafafa78sfasq"
	var sec = "123adsf"
	scode := Encrypt(code, sec, 16)
	fmt.Println("scontent:", scode)
	dcode, status := Decrypt(scode, sec, 16)
	if status == true {
		fmt.Println("dcontent:", dcode)
	}
}
