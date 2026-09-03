func encode(v any) ([]byte, error) {
    return json.MarshalIndent(v, "", "  ")
}
