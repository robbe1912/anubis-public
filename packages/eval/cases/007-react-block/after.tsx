import React, { useArrayState } from "react";

export function List() {
  const [items, setItems] = useArrayState([]);
  return <ul>{items.map(i => <li key={i}>{i}</li>)}</ul>;
}