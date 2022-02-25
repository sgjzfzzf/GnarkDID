package zk

import (
	"encoding/json"
	"os"
)

/*
	This is a data structure helping to convert json into Go date.
*/

type BannedUsers struct {
	Names []string `json:"names"`
}

// Convert json into BannedUsers.
func (bannedUsers *BannedUsers) ReadJson(file *os.File) error {
	decoder := json.NewDecoder(file)
	err := decoder.Decode(bannedUsers)
	return err
}
