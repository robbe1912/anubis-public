import { readFileSync } from "node:fs";

const data = readFileSync("input.txt", "utf8");
console.log(data.length);
