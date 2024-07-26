import { createContext } from "react";

export const AnalysisContext = createContext({
    selected_function: null,
    all_functions: [],
    func_history: [],
    func_banner: ''
});