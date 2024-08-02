import { useState, useContext, useEffect } from "react";
import { AnalysisContext } from "../context/AnalysisContext";
import {
    ReactFlow,
    ReactFlowProvider,
    Controls,
    Background,
    useNodesState,
    useEdgesState,
    MarkerType
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import CodeNode from "./CodeNode";
import axios from "axios";

const initialNodePosition = (index) => {
    return { x: index * 250, y: 100 };
};

const nodeTypes = {
    codeNode: CodeNode
}

const convertToReactFlowFormat = (graph) => {
    const nodes = graph.nodes.map((node, index) => ({
        id: node.id.toString(),
        position: initialNodePosition(index),
        data: { label: `Node ${node.id}`, text: '' },
        type: 'codeNode',
        draggable: true
    }));

    const edges = graph.edges.map((edge, index) => ({
        id: `edge-${index}`,
        source: edge.src.toString(),
        target: edge.dst.toString(),
        type: 'smoothstep',
        markerEnd: {
            type: MarkerType.ArrowClosed,
          },
    }));
    console.log("EDGES")
    console.log(edges)

    return { nodes, edges };
};

export default function Graph() {
    const [analysisContext] = useContext(AnalysisContext);
    const [graph, setGraph] = useState(null);
    const [nodes, setNodes, onNodesChange] = useNodesState([]);
    const [edges, setEdges, onEdgesChange] = useEdgesState([]);

    useEffect(() => {
        if (analysisContext.graphSet) {
            const convertedGraph = convertToReactFlowFormat(analysisContext.graph);
            setGraph(convertedGraph);
            //setNodes(convertedGraph.nodes);
            setEdges(convertedGraph.edges);

            // Prepare to fetch disassembly data for each node
            const disasmRequests = convertedGraph.nodes.map(node =>
                axios.post(`${import.meta.env.VITE_BACKEND}api/disasms/`, { "block_id": node.id })
            );

            // Execute all requests and update nodes once all responses are received
            Promise.all(disasmRequests)
                .then(responses => {
                    const updatedNodes = convertedGraph.nodes.map((node, index) => {
                        const disasmData = responses[index].data;
                        let text = []
                        let disasmString = [];
                        for (let j = 0; j < disasmData.length; j++) {
                            disasmString.push(`${disasmData[j].addr}: ${disasmData[j].op} ${disasmData[j].data}\n`);
                            console.log(disasmString);
                            text.push({"addr": disasmData[j].addr, "op": disasmData[j].op, "data": disasmData[j].data})
                        }
                        return {
                            ...node,
                            data: { label: `test`, text: text }
                        };
                    });
                    console.log("Updated nodes")
                    console.log(updatedNodes);
                    setNodes(updatedNodes);
                })
                .catch(error => {
                    console.error("Error fetching disassemblies:", error);
                });
        }
    }, [analysisContext.graph]);

    if (!graph) {
        return <div>Not selected</div>;
    }

    return (
        <div className="component-wrapper" style={{ height: '33vh' }}>
            <ReactFlowProvider>
                <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    onNodesChange={onNodesChange}
                    // onEdgesChange={onEdgesChange}
                    nodeTypes={nodeTypes}
                >
                    <Controls />
                    <Background />
                </ReactFlow>
            </ReactFlowProvider>
        </div>
    );
}
