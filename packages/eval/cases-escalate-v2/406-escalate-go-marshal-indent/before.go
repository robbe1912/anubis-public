func encode(v any) ([]byte, error) {
    return json.Marshal(v)
}
