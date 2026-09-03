import { readFileSync } from "node:fs";

const data = readFileSync("input.txt", "utf8");
const lines = data.split("\n");
console.log(lines.length);
