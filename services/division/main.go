package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"os"
)

func get_g_p(size string) (g, p *big.Int) {

	if size == "512" {
		p, _ = new(big.Int).SetString("FCA682CE8E12CABA26EFCCF7110E526DB078B05EDECBCD1EB4A208F3AE1617AE01F35B91A47E6DF63413C5E12ED0899BCD132ACD50D99151BDC43EE737592E17", 16)

		g, _ = new(big.Int).SetString("678471B27A9CF44EE91A49C5147DB1A9AAF244F05A434D6486931D2D14271B9E35030B71FD73DA179069B32E2935630E1C2062354D0DA20A6C416E50BE794CA4", 16)

	}
	if size == "768" {
		p, _ = new(big.Int).SetString("E9E642599D355F37C97FFD3567120B8E25C9CD43E927B3A9670FBEC5D890141922D2C3B3AD2480093799869D1E846AAB49FAB0AD26D2CE6A22219D470BCE7D777D4A21FBE9C270B57F607002F3CEF8393694CF45EE3688C11A8C56AB127A3DAF", 16)

		g, _ = new(big.Int).SetString("30470AD5A005FB14CE2D9DCD87E38BC7D1B1C5FACBAECBE95F190AA7A31D23C4DBBCBE06174544401A5B2C020965D8C2BD2171D3668445771F74BA084D2029D83C1C158547F3A9F1A2715BE23D51AE4D3E5A1F6A7064F316933A346D3F529252", 16)

	}
	if size == "1024" {
		p, _ = new(big.Int).SetString("FD7F53811D75122952DF4A9C2EECE4E7F611B7523CEF4400C31E3F80B6512669455D402251FB593D8D58FABFC5F5BA30F6CB9B556CD7813B801D346FF26660B76B9950A5A49F9FE8047B1022C24FBBA9D7FEB7C61BF83B57E7C6A8A6150F04FB83F6D3C51EC3023554135A169132F675F3AE2B61D72AEFF22203199DD14801C7", 16)

		g, _ = new(big.Int).SetString("F7E1A085D69B3DDECBBCAB5C36B857B97994AFBBFA3AEA82F9574C0B3D0782675159578EBAD4594FE67107108180B449167123E84C281613B7CF09328CC8A6E13C167A8B547C8D28E0A3AE1E2BB3A675916EA37F0BFA213562F1FB627A01243BCCA4F1BEA8519089A883DFE15AE59F06928B665E807B552564014C3BFECF492A", 16)

	}
	return
}

type PublicKey struct {
	G, P, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	X *big.Int
}

func Encrypt(random io.Reader, pub *PublicKey, msg string) (a, b *big.Int, err error) {

	k, _ := rand.Int(random, pub.P)

	m, _ := new(big.Int).SetString(msg, 10)

	a = new(big.Int).Exp(pub.G, k, pub.P)
	s := new(big.Int).Exp(pub.Y, k, pub.P)
	b = s.Mul(s, m)
	b.Mod(b, pub.P)

	return
}

func Decrypt(priv *PrivateKey, a, b *big.Int) (msg []byte, err error) {
	s := new(big.Int).Exp(a, priv.X, priv.P)
	s.ModInverse(s, priv.P)
	s.Mul(s, b)
	s.Mod(s, priv.P)
	em := s.Bytes()

	return em, nil
}

func valint(a []byte) (i int) {
	if len(a) == 1 {
		i = int(a[0])
	}
	if len(a) == 2 {
		i = (int(a[0]) << 8) + int(a[1])
	}
	if len(a) == 3 {
		i = (int(a[0]) << 16) + int(a[1])<<8 + int(a[2])
	}
	if len(a) == 4 {
		i = (int(a[0]) << 24) + int(a[1])<<16 + int(a[2])<<8 + int(a[3])
	}
	return
}

func main() {

	x := "40"
	plen := "512"
	val1 := "8"
	val2 := "4"

	argCount := len(os.Args[1:])

	if argCount > 0 {
		val1 = string(os.Args[1])
	}
	if argCount > 1 {
		val2 = string(os.Args[2])
	}
	if argCount > 2 {
		x = string(os.Args[3])
	}
	if argCount > 3 {
		plen = string(os.Args[4])
	}

	fmt.Printf("Prime number size: %s\n\n", plen)

	xval, _ := new(big.Int).SetString(x, 10)

	g, p := get_g_p(plen)

	priv := &PrivateKey{
		PublicKey: PublicKey{
			G: g,
			P: p,
		},
		X: xval,
	}

	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)

	a1, b1, _ := Encrypt(rand.Reader, &priv.PublicKey, val1)
	a2, b2, _ := Encrypt(rand.Reader, &priv.PublicKey, val2)

	a2 = a2.ModInverse(a2, priv.P)
	b2 = b2.ModInverse(b2, priv.P)

	message2, _ := Decrypt(priv, a1.Mul(a1, a2), b1.Mul(b1, b2))

	fmt.Printf("====Values (val1=%s and val2=%s)\n", val1, val2)
	fmt.Printf("====Private key (x):\nX=%d", priv.X)
	fmt.Printf("\n\n====Public key (Y,G,P):\nY=%d\nG=%d\nP=%d", priv.Y, priv.PublicKey.G, priv.PublicKey.P)

	fmt.Printf("\n\n====Cipher (a1=%s)\n\n(b1=%s): ", a1, b1)
	fmt.Printf("\n\n====Decrypted: %d\n", valint(message2))

}
