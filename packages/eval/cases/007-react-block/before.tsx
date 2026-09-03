import React, { useState } from "react";

export function List() {
  const [items, setItems] = useState([]);
  return <ul>{items.map(i => <li key={i}>{i}</li>)}</ul>;
}