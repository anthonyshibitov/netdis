import { createContext } from "react";

export const AnalysisContext = createContext({
    selectedFunction: null,
    allFunctions: [],
    funcHistory: [],
    funcBanner: '',
    graph: {},
    graphSet: false
});