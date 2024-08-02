import { useLocation } from "react-router-dom";
import FunctionList from "../components/FunctionList.jsx";
import Listing from "../components/Listing.jsx";
import { AnalysisContext } from "../context/AnalysisContext.js";
import { useState } from "react";
import './AnalysisPage.css'
import Graph from "../components/Graph.jsx";

export default function AnalysisPage() {
    const state = useLocation();
    console.log("STATE TO ANALYSIS");
    console.log(state);

    const [analysisContext, setAnalysisContext] = useState({"selected_function": null});

    return (
        <AnalysisContext.Provider value={[analysisContext, setAnalysisContext]}>
            <div className="analysis-container">
                <FunctionList funcs={state.state}/>
                <Listing />
                <Graph />
            </div>
        </AnalysisContext.Provider>
    )
}