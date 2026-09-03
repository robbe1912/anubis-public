package main
import "encoding/json"
type User struct {
  Name string `json:"name"`
}
func encode(u User) ([]byte, error) {
  return json.Marshal(u)
}
