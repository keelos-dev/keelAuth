// phonesim is a phone without the phone: the reference for keelApp (keelAuth docs/04) and
// the test of the phone module. It keeps its key in a JSON file.
//
//	phonesim enrol -key phone.json -url 'keelauth://enroll?o=…&c=…' [-name NAME]
//	phonesim login -key phone.json -url 'keelauth://login?o=…&c=…&n=…'
//
// The TLS certificate is not checked (keelAuth's own CA): a reference, not a product.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"keelauth/internal/module/phone"
)

type keyFile struct {
	Origin string `json:"origin"`
	Device string `json:"device"`
	User   string `json:"user"`
	Key    []byte `json:"key"` // the private key, PKCS#8
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: phonesim enrol|login -key FILE -url URL [-name NAME]\n       phonesim rp -key FILE -aud HOST -c ID -n NONCE")
	}
	if os.Args[1] == "rp" {
		rp(os.Args[2:])
		return
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	keyPath := fs.String("key", "phone.json", "the phone's key file")
	rawURL := fs.String("url", "", "what the QR code says")
	name := fs.String("name", "phonesim", "the phone's name (enrol)")
	via := fs.String("via", "", "reach keelauthd here instead of the code's origin (a port forward); the signatures still name the origin")
	fs.Parse(os.Args[2:])
	u, err := url.Parse(*rawURL)
	if err != nil || u.Scheme != "keelauth" {
		fail("-url: a keelauth:// URL from the QR code")
	}
	q := u.Query()
	origin := q.Get("o")
	at := origin
	if *via != "" {
		at = *via
	}
	switch os.Args[1] {
	case "enrol":
		if u.Host != "enroll" {
			fail("not an enrolment code")
		}
		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(priv)
		code := q.Get("c")
		out := post(at+"/phone/enroll", map[string]string{"code": code, "name": *name, "platform": "sim",
			"key": phone.EncodeKey(&priv.PublicKey), "sig": phone.Sign(priv, "keelauth-enroll\n"+origin+"\n"+code)})
		kf := keyFile{Origin: origin, Device: out["device"].(string), User: out["user"].(string), Key: der}
		b, _ := json.MarshalIndent(kf, "", "  ")
		if err := os.WriteFile(*keyPath, b, 0o600); err != nil {
			fail(err.Error())
		}
		fmt.Printf("enrolled as %s (device %s) at %s\n", kf.User, kf.Device, kf.Origin)
	case "login":
		if u.Host != "login" {
			fail("not a login code")
		}
		b, err := os.ReadFile(*keyPath)
		if err != nil {
			fail(err.Error())
		}
		var kf keyFile
		if err := json.Unmarshal(b, &kf); err != nil {
			fail(err.Error())
		}
		if kf.Origin != origin {
			fail(fmt.Sprintf("the code is for %s, this phone is enrolled at %s", origin, kf.Origin))
		}
		k, err := x509.ParsePKCS8PrivateKey(kf.Key)
		if err != nil {
			fail(err.Error())
		}
		priv := k.(*ecdsa.PrivateKey)
		id, nonce := q.Get("c"), q.Get("n")
		post(at+"/phone/approve", map[string]string{"c": id, "n": nonce, "device": kf.Device,
			"sig": phone.Sign(priv, "keelauth-login\n"+origin+"\n"+id+"\n"+nonce)})
		fmt.Printf("approved login as %s\n", kf.User)
	default:
		fail("enrol or login")
	}
}

// rp approves a login at another system (docs/04 §8): it signs phone.RPMessage for the
// system's host name and challenge and prints what the phone would send there, as JSON
// ({"o", "device", "sig"}). It posts nothing: every system has its own call for this.
func rp(args []string) {
	fs := flag.NewFlagSet("rp", flag.ExitOnError)
	keyPath := fs.String("key", "phone.json", "the phone's key file")
	aud := fs.String("aud", "", "the system's host name (what it checks the signature with)")
	id := fs.String("c", "", "the system's challenge id")
	nonce := fs.String("n", "", "the challenge's nonce")
	fs.Parse(args)
	b, err := os.ReadFile(*keyPath)
	if err != nil {
		fail(err.Error())
	}
	var kf keyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		fail(err.Error())
	}
	k, err := x509.ParsePKCS8PrivateKey(kf.Key)
	if err != nil {
		fail(err.Error())
	}
	msg := phone.RPMessage(kf.Origin, *aud, *id, *nonce)
	if msg == "" {
		fail("rp: -aud, -c and -n are needed (no line breaks)")
	}
	out, _ := json.Marshal(map[string]string{"o": kf.Origin, "device": kf.Device, "sig": phone.Sign(k.(*ecdsa.PrivateKey), msg)})
	fmt.Println(string(out))
}

func post(to string, body map[string]string) map[string]any {
	b, _ := json.Marshal(body)
	c := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := c.Post(to, "application/json", bytes.NewReader(b))
	if err != nil {
		fail(err.Error())
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	json.Unmarshal(rb, &out)
	if resp.StatusCode != 200 {
		fail(fmt.Sprintf("%s: %d %s", to, resp.StatusCode, rb))
	}
	return out
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "phonesim:", msg)
	os.Exit(1)
}
