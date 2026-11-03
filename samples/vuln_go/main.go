// Intentionally vulnerable program. Scanner fixture only.
package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

const apiToken = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func lookup(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

func ping(host string) ([]byte, error) {
	return exec.Command("sh", "-c", "ping -c 1 "+host).Output()
}

func digest(data []byte) string {
	return fmt.Sprintf("%x", md5.Sum(data))
}

func client() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		out, _ := ping(r.URL.Query().Get("host"))
		w.Write(out)
	})
	_ = http.ListenAndServe(":8080", nil)
}
