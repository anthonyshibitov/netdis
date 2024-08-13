import { createContext } from "react";

export const MenuContext = createContext({
    disasmView: true,
    decompView: true,
    functionView: true,
    cfgView: true,
});