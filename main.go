package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"

	"github.com/joho/godotenv"
)

func getSignature(body []byte) string {
	key := []byte(os.Getenv("GITHUBSECRET"))
	h := hmac.New(sha1.New, key)
	h.Write(body)
	hash := hex.EncodeToString(h.Sum(nil))
	return hash
}

func verifyBodySignature(expected string, body []byte) bool {
	current := "sha1=" + getSignature(body)
	expectedb := []byte(expected)
	currentb := []byte(current)
	if subtle.ConstantTimeCompare(expectedb, currentb) == 1 {
		return true
	} else {
		return false
	}
}

func saveBodyToFile(body []byte) {
	ioutil.WriteFile("request.body.bin", body, 0644)
}

func verifySender(body []byte) bool {
	var f interface{}
	err := json.Unmarshal(body, &f)
	if err != nil {
		return false
	}
	// fmt.Print(f.sender)
	m := f.(map[string]interface{})
	m2 := m["sender"].(map[string]interface{})
	spew.Dump(m2["login"])
	spew.Dump(os.Getenv("GITHUBUSERNAME"))
	var login = m2["login"].(string)
	if subtle.ConstantTimeCompare([]byte(os.Getenv("GITHUBUSERNAME")), []byte(login)) == 1 {
		return true
	} else {
		return false
	}
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	saveBodyToFile(body)

	if err != nil {
		log.Fatal("Cannot read from body...")
	}

	verifiedHash := verifyBodySignature(r.Header.Get("X-Hub-Signature"), body)
	if verifiedHash == false {
		w.WriteHeader(403)
		return
	}

	verifiedSender := verifySender(body)
	if verifiedSender == false {
		w.WriteHeader(403)
		return
	}

}

func forbidden(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(403)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading env file")
	}
	port := os.Getenv("PORT")

	r := mux.NewRouter()
	r.HandleFunc("/", mainHandler).Methods("POST")
	r.HandleFunc("/", forbidden)

	address := fmt.Sprintf(":%s", port)
	log.Printf("Listening on %s", address)

	err = http.ListenAndServe(address, r)
	if err != nil {
		log.Fatal("Listen and serve: ", err)
	}
}
