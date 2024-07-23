import { useLocation } from "react-router-dom";
import FunctionList from "../components/FunctionList.jsx";
import Listing from "../components/Listing.jsx";
import { AnalysisContext } from "../context/AnalysisContext.js";
import { useState } from "react";

export default function AnalysisPage() {
    const { state } = useLocation();
    const [analysisContext, setAnalysisContext] = useState({"selected_function": null});

    return (
        <AnalysisContext.Provider value={[analysisContext, setAnalysisContext]}>
            <FunctionList funcs={state}/>
            <Listing />
        </AnalysisContext.Provider>
    )
}