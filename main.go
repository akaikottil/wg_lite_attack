package main

import (
	"noise"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"math/big"
	"os"
	"os/exec"
	"strconv"
)

var BinaryfilePath = "/Users/akshaykaikottil/go/src/wg-lite-master/wg-lite"

// Re-used from wg-lite git code
type RandomInc byte
func (r *RandomInc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*r)
		*r = (*r) + 1
	}
	return len(p), nil
}

// secret for ECDSA
var secret *big.Int = new(big.Int)

// Re-used from wg-lite git code
func genBadPriv() (k *big.Int) {
	k = new(big.Int).SetInt64(secret.Int64()) // exact value of k can be changed
	return
}

// Re-used from wg-lite git code
func generateKey(c elliptic.Curve) *ecdsa.PrivateKey {
	k := genBadPriv()
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv
}


func createNoiseHandshakeState() *noise.HandshakeState {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	ecdsakey := generateKey(elliptic.P256())

	rngI := new(RandomInc)
	staticI, _ := cs.GenerateKeypair(rngI)

	var privbytes [32]byte
	staticRbad, _ := noise.GenerateBadKeypair(ecdsakey.D.FillBytes(privbytes[:]))

	hsI, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       noise.HandshakeIKSign,
		Initiator:     true,
		Prologue:      []byte("ABC"),
		StaticKeypair: staticI,
		PeerStatic:    staticRbad.Public,
		VerifyingKey:  ecdsakey.Public().(*ecdsa.PublicKey),
	})

	return hsI
}

func runcmd(BinaryfilePath string, arg1 string, arg2 string, arg3 string, arg4 string, arg5 string, arg6 string) () {
	_, err := exec.Command(BinaryfilePath, arg1, arg2, arg3, arg4, arg5, arg6).Output()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(0)
	}
}


func readMsgFile(filename string) ([]byte, *big.Int, *big.Int) {
	msg, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file")
		os.Exit(0)
	}
	sigatureLength := msg[len(msg)-1]
	hash := msg[:len(msg)-int(sigatureLength)-1]
	signature := msg[len(msg)-int(sigatureLength)-1 : len(msg)-1]

	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)

	input := cryptobyte.String(signature)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		fmt.Println("Error parsing ASN1 signature parameters")
		os.Exit(0)
	}

	return hash, r, s
}

//function to attack and retrieve nonce and secret
func protocolAttack() (string, *big.Int) {
	var (
		hashValue = make([][]byte, 2)
		r         = make([]*big.Int, 2)
		s    = make([]*big.Int, 2)
	)

	// run wg-lite twice with different seed values
	for i := 0; i < 2; i++ {
		incrementer := strconv.FormatInt(int64(i), 10)
		runcmd(BinaryfilePath, "client", incrementer, "1", "client-message-1", "server-message-1", "server-message-2")
		runcmd(BinaryfilePath, "server", incrementer, "1", "server-message-1", "client-message-1", "client-message-2")
		hashValue[i], r[i], s[i]=readMsgFile("server-message-1")
	}

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	ecdsakey := generateKey(elliptic.P256())

	hsM, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:  cs,
		VerifyingKey: ecdsakey.Public().(*ecdsa.PublicKey),
	})

	nonce := hsM.RecoverNonce(s, hashValue)
	secret := hsM.RecoverSecret(r[1], s[1], nonce, hashValue[1])

	return nonce, secret

}

//function imitates client to receive secret message
func spoofAttack() string {
	hsM := createNoiseHandshakeState()
	var cs1, cs2 *noise.CipherState

	// client sends handshake message
	msg, _, _, _ := hsM.WriteMessage(nil, nil)
	err := os.WriteFile("client-message-1", msg, 0666)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}

	// server sends handshake message
	runcmd(BinaryfilePath, "server", "2", "1", "server-message-1", "client-message-1", "client-message-2")

	// client request for a secret
	msg, _ = os.ReadFile("server-message-1")
	var res []byte
	res, cs1, cs2, err = hsM.ReadMessage(nil, msg)
	if err != nil {
		fmt.Println(err)
	}
	res, _ = cs1.Encrypt(nil, nil, []byte("secret"))

	if err = os.WriteFile("client-message-2", res, 0666); err != nil {
		fmt.Println(err)
	}

	// server responds with a secret
	runcmd(BinaryfilePath, "server", "2", "2", "server-message-2", "client-message-1", "client-message-2")

	serverSecret, _ := os.ReadFile("server-message-2")
	decryptedSecret, _ := cs2.Decrypt(nil, nil, serverSecret)

	return string(decryptedSecret)
}

func main(){
	if len(os.Args) > 1 {
		BinaryfilePath = os.Args[1]
	}
	noise.Nonce, secret = protocolAttack()
	hiddenSecret :=spoofAttack()
	fmt.Println(hiddenSecret)
}
