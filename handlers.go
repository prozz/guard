package guard

import (
	"io/ioutil"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

func KeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write(g.verifyBytes)
}

func SignInHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	username := vars["username"]
	password, err := ioutil.ReadAll(r.Body)
	if err != nil || len(password) == 0 || len(username) == 0 {
		http.Error(w, "Invalid username and/or password.", http.StatusUnauthorized)
		return
	}

	claims, err := g.auth.Claims(username, string(password))
	if err != nil {
		http.Error(w, "Invalid username and/or password.", http.StatusUnauthorized)
		return
	}

	token := jwt.New(jwt.SigningMethodHS256)
	for k, v := range claims {
		token.Claims[k] = v
	}

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(g.signKey)

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenString))
}

func VerifyHandler(w http.ResponseWriter, r *http.Request) {
	tokenBytes, err := ioutil.ReadAll(r.Body)
	if err != nil || len(tokenBytes) == 0 {
		http.Error(w, "Invalid token.", http.StatusUnauthorized)
	}

	token, err := jwt.Parse(string(tokenBytes), func(token *jwt.Token) (interface{}, error) {
		return g.verifyKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid username and/or password.", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}
