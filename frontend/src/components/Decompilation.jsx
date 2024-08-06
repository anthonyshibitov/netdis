import { useState, useContext, useEffect, useRef } from "react";
import axios from "axios";
import { AnalysisContext } from "../context/AnalysisContext";
import SyntaxHighlighter from 'react-syntax-highlighter';
import { a11yLight } from 'react-syntax-highlighter/dist/esm/styles/hljs';

export default function Decompilation() {
    const [analysisContext, setAnalysisContext] = useContext(AnalysisContext);

    if(analysisContext.decomp == ''){
        return (
            <div>No function selected</div>
        )
    }

    useEffect(() => {
        console.log("GOT CHANGE")
        console.log(analysisContext.decomp)
    }, [analysisContext.decomp])

    return (
        <div className="component-wrapper">
            <div className="component-title">Decompilation</div>
            <div className="component-body overflow-x-hidden font-mono text-xs">
                <code className="text-xs">
                    <pre>
                        <SyntaxHighlighter language="c" style={a11yLight}>
                            {analysisContext.decomp}
                        </SyntaxHighlighter>
                    </pre>
                </code>
            </div>
        </div>

    )
}