// Mutation M1: wrong named export from real package.
// `react-dom` exists; `useState` is exported by `react`, NOT `react-dom`.
// (react-dom exports render APIs: render, createRoot, flushSync, etc.)
// Expected runtime: SyntaxError / TypeError (undefined import).
// Expected scanner layer: L1.5 cached-hallucination OR forge: hallucinated-import-name.
import { useState } from "react-dom";

export function useCounter(initial: number) {
    const [count, setCount] = useState(initial);
    return { count, setCount };
}
