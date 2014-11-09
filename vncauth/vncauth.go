package vncauth;

//import ("os"; "fmt")
import "crypto/des"
//import "encoding/hex"

/*
func main() {
	challenge := []byte(os.Args[1])
	fmt.Println(hex.Dump(challenge))
	passwd := os.Args[2]
	response := vnc_auth(passwd, challenge)
	fmt.Println(hex.Dump(response))
}*/

func VncAuthResponse(challenge []byte, password string) []byte {
	des_key := append([]byte(password), 0, 0, 0, 0, 0, 0, 0, 0)
	des_key = des_key[0:8]
	for i := range des_key {
		c := des_key[i]
		// reverse bits in byte
		c = ((c & 0x01) << 7) + ((c & 0x02) << 5) + ((c & 0x04) << 3) + ((c & 0x08) << 1) +
		((c & 0x10) >> 1) + ((c & 0x20) >> 3) + ((c & 0x40) >> 5) + ((c & 0x80) >> 7)
		des_key[i] = c
	}
	
	cipher, _ := des.NewCipher(des_key)
	
	cipher.Encrypt(challenge[0:8], challenge[0:8])
	cipher.Encrypt(challenge[8:16], challenge[8:16])
	
	return challenge
}
