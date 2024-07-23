import { useContext, useState, useEffect } from "react";
import { AnalysisContext } from "../context/AnalysisContext";

export default function Listing() {
    const [analysisContext, setAnalysisContext] = useContext(AnalysisContext);
    const [f, setF] = useState("No function selected");

    useEffect(() => {
        if(analysisContext.selected_function != null){
            setF(`Selected function: ${analysisContext.selected_function}`);
        }
    }, [analysisContext]);

    return (
        <>{f}</>
    )
}