const data = JSON.parse(text, (key, value) => {
  if (typeof value === "string") return value.trim();
  return value;
});
