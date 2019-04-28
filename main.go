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
	"os/exec"
	"path/filepath"
	"strings"

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
	}
	return false
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
	var login = m2["login"].(string)
	if subtle.ConstantTimeCompare([]byte(os.Getenv("GITHUBUSERNAME")), []byte(login)) == 1 {
		return true
	}

	return false
}

func serializeError(message string) string {
	return fmt.Sprintf("{\"error\": \"%s\"}", message)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Main handler opened")
	body, err := ioutil.ReadAll(r.Body)
	saveBodyToFile(body)

	if err != nil {
		log.Fatal("Cannot read from body....")
	}

	verifiedHash := verifyBodySignature(r.Header.Get("X-Hub-Signature"), body)
	if verifiedHash == false {
		w.Write([]byte("{\"error\": \"Wrong hash\"}"))
		w.WriteHeader(403)
		return
	}
	log.Println("Hash zweryfikowany")

	verifiedSender := verifySender(body)
	if verifiedSender == false {
		w.Write([]byte("{\"error\": \"Wrong Sender\"}"))
		w.WriteHeader(403)
		return
	}
	log.Println("Sender zweryfikowany")

	ghook := ParseHook(body)

	if ghook.BranchName() != "master" {
		log.Printf("Nazwa brancha jest inn niż master - nie kontynuuję: '%s'\n", ghook.BranchName())
		return
	}
	log.Println("Branch jest master")

	dir := os.Getenv("SCRIPTS_DIR")
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Printf("Błąd podczas listowania katalogu %s", err)
	}
	log.Printf("Katalog ze skryptami zlistowany liczba obiektów: %d", len(files))

	scriptFiles := make([]string, 0)
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		scriptFiles = append(scriptFiles, filepath.Join(dir, f.Name()))
	}
	log.Printf("Katalog ze skryptami ma %d plików", len(files))

	matchedFiles := make([]string, 0)
	for _, f := range scriptFiles {
		filename := filepath.Base(f)
		if strings.Contains(filename, ghook.Repository.Name) {
			matchedFiles = append(matchedFiles, f)
		}
	}
	log.Printf("Pasujące pliki: \n")
	log.Printf(spew.Sprint(matchedFiles))

	if len(matchedFiles) == 0 {
		log.Println("Żaden z plików nie odpowiada nazwie repozytoriów, dostępne pliki poniżej - przerywam")
		log.Println(spew.Sdump(scriptFiles))
		return
	}

	if len(matchedFiles) != 1 {
		log.Printf("Występuje więcej niż jeden skrypt - przerywam")
		log.Printf(spew.Sprint(matchedFiles))
		w.Write([]byte(serializeError(err.Error())))
		return
	}

	cmd := exec.Command(matchedFiles[0])
	out, err := cmd.Output()
	if err != nil {
		log.Fatalf("Błąd podczas skryptu: %s\n", err)
		w.Write([]byte(serializeError(err.Error())))
		return
	}
	log.Printf("Skrypt nie zgłosił błędu wyjście:\n%s", out)
}

func forbidden(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(403)
}

func checkVariables() bool {
	result := true
	vars := [...]string{"GITHUBUSERNAME", "GITHUBSECRET", "PORT", "SCRIPTS_DIR"}

	for _, v := range vars {
		if os.Getenv(v) == "" {
			log.Printf("Env variable %s is not set", v)
			result = false
		}
	}
	return result
}

func main() {
	godotenv.Load()

	if checkVariables() == false {
		log.Println("Set variables and run again...")
		log.Println("exiting")
		return
	}

	port := os.Getenv("PORT")

	r := mux.NewRouter()
	r.HandleFunc("/", mainHandler).Methods("POST")
	r.HandleFunc("/", forbidden)

	address := fmt.Sprintf(":%s", port)
	log.Printf("Listening on %s", address)

	err := http.ListenAndServe(address, r)
	if err != nil {
		log.Fatal("Listen and serve: ", err)
	}
}
