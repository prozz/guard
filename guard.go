package guard

import (
	"crypto/rsa"
	"io/ioutil"
	"log"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

type Auth interface {
	Claims(username, password string) (map[string]string, error)
}

type Guard struct {
	auth        Auth
	verifyBytes []byte
	verifyKey   *rsa.PublicKey
	signBytes   []byte
	signKey     *rsa.PrivateKey
}

// openssl genrsa -out app.rsa keysize
// openssl rsa -in app.rsa -pubout > app.rsa.pub

var g *Guard = &Guard{}

func Init(auth Auth, publicKeyPath, privateKeyPath string) *Guard {
	signBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		log.Fatal(err)
	}
	verifyBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		log.Fatal(err)
	}

	g.auth = auth
	g.verifyBytes = verifyBytes
	g.verifyKey = verifyKey
	g.signBytes = signBytes
	g.signKey = signKey
	return g
}

func StartServer() {
	r := mux.NewRouter()
	r.HandleFunc("/public-key", KeyHandler).Methods("GET")
	r.HandleFunc("/sign-in/{username}", SignInHandler).Methods("POST")
	r.HandleFunc("/verify", VerifyHandler).Methods("POST")

	http.Handle("/", r)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
