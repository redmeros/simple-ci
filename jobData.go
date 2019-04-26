package main

import (
	"encoding/json"
	"regexp"
)

// GHHook to reprezentacja w go webhooka
// z githuba
type GHHook struct {
	Ref        string `json:"ref"`
	Before     string `json:"before"`
	After      string `json:"after"`
	Repository struct {
		Name string `json:"name"`
	} `json:"repository"`
}

// ParseHook parsuje push event z ghookithuba
// i zwraca GHook
func ParseHook(body []byte) GHHook {
	var h GHHook
	json.Unmarshal(body, &h)
	return h
}

// BranchName Na podstawie Ref'a i wyrażenia regularnego
// zwraca nazwę brancha
func (h GHHook) BranchName() string {
	var re = regexp.MustCompile(`/(?P<bname>[a-zA-Z0-9]+)$`)

	w := re.FindStringSubmatch(h.Ref)

	if len(w) < 2 {
		return ""
	}

	return w[1]
}
