import React, { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import FunctionList from "../components/FunctionList.jsx";
import Listing from "../components/Listing.jsx";
import { AnalysisContext } from "../context/AnalysisContext.js";
import './AnalysisPage.css';
import Graph from "../components/Graph.jsx";
import GridLayout from "react-grid-layout";
import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";
import { NodeSizeProvider } from "../context/NodeSizeContext.jsx";

const AnalysisPage = () => {
    const { state } = useLocation();
    const [analysisContext, setAnalysisContext] = useState({ "selectedFunction": null });

    const [dimensions, setDimensions] = useState({ width: window.innerWidth, height: window.innerHeight });

    useEffect(() => {
        const handleResize = () => {
            setDimensions({ width: window.innerWidth, height: window.innerHeight });
        };

        window.addEventListener('resize', handleResize);
        return () => window.removeEventListener('resize', handleResize);
    }, []);

    const layout = [
        { i: "a", x: 0, y: 0, w: 4, h: 4, minW: 3, minH: 3 },
        { i: "b", x: 4, y: 0, w: 4, h: 4, minW: 3, minH: 3 },
        { i: "c", x: 8, y: 0, w: 4, h: 4, minW: 3, minH: 3 }
    ];

    return (
        <AnalysisContext.Provider value={[analysisContext, setAnalysisContext]}>
            <GridLayout
                className="layout"
                layout={layout}
                cols={12}
                rowHeight={Math.floor(dimensions.height / 10)}
                width={dimensions.width}
                isDraggable={true}
                isResizable={true}
                draggableHandle=".draggable-handle"
            >
                <div key="a">
                    <div className="draggable-handle"></div>
                    <FunctionList functionListProps={state} />
                </div>
                <div key="b">
                    <div className="draggable-handle"></div>
                    <Listing />
                </div>
                <div key="c">
                    <div className="draggable-handle"></div>
                    <NodeSizeProvider>
                        <Graph />
                    </NodeSizeProvider>
                </div>
            </GridLayout>
        </AnalysisContext.Provider>
    );
};

export default AnalysisPage;
