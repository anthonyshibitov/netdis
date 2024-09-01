import React, { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import FunctionList from "../components/FunctionList.jsx";
import Listing from "../components/Listing.jsx";
import { AnalysisContext } from "../context/AnalysisContext.js";
import { MenuContext } from "../context/MenuContext.jsx";
import './AnalysisPage.css';
import Graph from "../components/Graph.jsx";
import GridLayout from "react-grid-layout";
import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";
import { NodeSizeProvider } from "../context/NodeSizeContext.jsx";
import Decompilation from "../components/Decompilation.jsx";
import MenuBar from "../components/Menubar.jsx";
import RawHex from "../components/RawHex.jsx";

const AnalysisPage = () => {
    const { state } = useLocation();
    const [analysisContext, setAnalysisContext] = useState({ "selectedFunction": null });
    const [menuContext, setMenuContext] = useState({
        disasmView: true, 
        decompView: true, 
        cfgView: true, 
        functionView: true, 
        rawView: true,
        uploadModal: false,
    });

    const [dimensions, setDimensions] = useState({ 
        width: window.innerWidth, 
        height: window.innerHeight 
    });

    useEffect(() => {
        const handleResize = () => {
            setDimensions({ width: window.innerWidth, height: window.innerHeight });
        };

        window.addEventListener('resize', handleResize);
        // window.location.reload();
        return () => window.removeEventListener('resize', handleResize);
    }, []);

    const layout = [
        { i: "funcs",  x: 10, y: 0, w: 6, h: 8, minW: 3, minH: 3 },
        { i: "disasm", x: 10, y: 9, w: 10, h: 8, minW: 3, minH: 3 },
        { i: "cfg",    x: 0, y: 0, w: 10, h: 8, minW: 3, minH: 3 },
        { i: "decomp", x: 0, y: 9, w: 10, h: 8, minW: 3, minH: 3 },
        { i: "hex",    x: 16, y: 0, w: 4, h: 8, minW: 4, minH: 3 }
    ];

    return (
        <AnalysisContext.Provider value={[analysisContext, setAnalysisContext]}>
            <MenuContext.Provider value={[menuContext, setMenuContext]}>
                <MenuBar />
                <GridLayout
                    className="layout"
                    layout={layout}
                    cols={20}
                    rowHeight={Math.floor(dimensions.height / 20)}
                    width={dimensions.width}
                    isDraggable={true}
                    isResizable={true}
                    draggableHandle=".draggable-handle"
                >
                    {menuContext.functionView &&
                    <div key="funcs">
                        <div className="draggable-handle">Functions</div>
                        <FunctionList functionListProps={state} />
                    </div>
                    }
                    {menuContext.disasmView &&
                    <div key="disasm">
                        <div className="draggable-handle">Disassembly</div>
                        <Listing />
                    </div>
                    }
                    {menuContext.cfgView &&
                    <div key="cfg">
                        <div className="draggable-handle">Control Flow Graph</div>
                        <NodeSizeProvider>
                            <Graph />
                        </NodeSizeProvider>
                    </div>
                    }
                    {menuContext.decompView && 
                    <div key="decomp">
                        <div className="draggable-handle">Decompilation</div>
                        <Decompilation />
                    </div>
                    }
                    {menuContext.rawView &&
                    <div key="hex">
                        <div className="draggable-handle">Raw Hex</div>
                        <RawHex rawhexProps={state}/>
                    </div>
                    }
                </GridLayout>
            </MenuContext.Provider>
        </AnalysisContext.Provider>
    );
};

export default AnalysisPage;
