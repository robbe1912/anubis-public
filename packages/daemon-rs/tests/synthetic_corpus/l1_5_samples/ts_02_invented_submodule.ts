// Mutation M2: invented submodule of real package.
// `lodash` exists; `lodashfp` does not (the real lodash FP build is
// `lodash/fp`, not a separate `lodashfp` package).
// Expected runtime: ModuleNotFoundError / Cannot find module 'lodashfp'.
// Expected scanner layer: L1.5 cached-hallucination OR forge: hallucinated-import.
import { map } from "lodashfp";

export const doubled = (xs: number[]) => map(xs, (x: number) => x * 2);
