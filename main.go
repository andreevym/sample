package main


import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
)

func main() {
	test()
}

func test() {
	privateKeyStr := "53aee6a2308ea4c4ad7f6dae1bdf12f41726e9989dee1e78e5f39461cc6681655475768991ed67e2d7ab65fa6109f3993b4324fbdd164541efccd71a2f5ed669"
	private, _ := hex.DecodeString(privateKeyStr)
	ekey := ed25519.PrivateKey(private)
	public := ekey.Public().(ed25519.PublicKey)
	fmt.Println(hex.EncodeToString(public))
	fmt.Printf("%x\n", public)
	fmt.Printf("%v\n", public)
	publicKey, _ := ssh.NewPublicKey(public)

	pemKey := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(ekey),
	}
	privateKey := pem.EncodeToMemory(pemKey)
	authorizedKey := ssh.MarshalAuthorizedKey(publicKey)

	_ = ioutil.WriteFile("id_ed25519", privateKey, 0600)
	_ = ioutil.WriteFile("id_ed25519.pub", authorizedKey, 0644)
}

func test2() {
	public := "b7ebc212b99ef23f422fae3121e1b32fce8eb5f436a5fefd1b1866def24ce284"
	res, err := hex.DecodeString(public)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	key := ed25519.PublicKey(res)
	publicKey, err := ssh.NewPublicKey(key)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	authorizedKey := ssh.MarshalAuthorizedKey(publicKey)
	fmt.Printf("%s\n", authorizedKey)
}

func test3() {
	public := "b7ebc212b99ef23f422fae3121e1b32fce8eb5f436a5fefd1b1866def24ce284"
	res, err := hex.DecodeString(public)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	key := ed25519.PublicKey(res)
	publicKey, err := ssh.NewPublicKey(key)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	authorizedKey := ssh.MarshalAuthorizedKey(publicKey)
	fmt.Printf("%s\n", authorizedKey)

	//pemKey := &pem.Block{
	//	Type:  "OPENSSH PRIVATE KEY",
	//	Bytes: edkey.MarshalED25519PrivateKey(privKey),
	//}
	//privateKey := pem.EncodeToMemory(pemKey)
	//authorizedKey := ssh.MarshalAuthorizedKey(publicKey)

	//_ = ioutil.WriteFile("id_ed25519", privateKey, 0600)
	_ = ioutil.WriteFile("id_ed25519.pub", authorizedKey, 0644)
}
