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
import ELK from 'elkjs/lib/elk.bundled.js';
import { NodeSizeContext, NodeSizeProvider } from "../context/NodeSizeContext.jsx";

const elk = new ELK();

const nodeWidth = 400;
const nodeHeight = 600;

const nodeTypes = {
    codeNode: CodeNode
}

const layoutGraph = async (nodes, edges, nodeSizes) => {
    console.log(" THIS SHOULD HAPPEN LAST! layoutGraph node sizes")
    console.log("HERES NODES")
    console.log(nodes)
    console.log("HERES EDGES")
    console.log(edges)

    const nodeIds = new Set(nodes.map(node => node.id));

    // Remove edges where the destination is a blank node
    const validEdges = edges.filter(edge => nodeIds.has(edge.source) && nodeIds.has(edge.target));
    
    const graph = {
        id: 'root',
        layoutOptions: {
            'elk.algorithm': 'layered',
            'elk.direction': 'DOWN',
            'elk.topdownLayout': true,
            'elk.topdown.nodeType': 'ROOT_NODE',
        },
        children: nodes.map(node => ({
            id: node.id,
            width: nodeSizes[node.id]?.width + 30 || nodeWidth,
            height: nodeSizes[node.id]?.height + 30 || nodeHeight
        })),
        edges: validEdges.map(edge => ({
            id: edge.id,
            sources: [edge.source],
            targets: [edge.target]
        }))
    };
    const layout = await elk.layout(graph);
    const positionedNodes = layout.children.map(node => ({
        ...nodes.find(n => n.id === node.id),
        position: {
            x: node.x,
            y: node.y,
        }
    }));

    return { nodes: positionedNodes, edges };
};

const convertToReactFlowFormat = async (graph, nodeSizes) => {
    const nodes = graph.nodes.map(node => ({
        id: node.id.toString(),
        position: {x: 0, y: 0},
        data: { label: `Node ${node.id}`, text: '' },
        type: 'codeNode',
        draggable: true,
        nodesConnectable: false,
    }));

    const edges = graph.edges.map((edge, index) => {
        //Find edge where source is the same, but target is different
        let color = 'black';
        if(edge.type == "conditional"){
            color = 'green';
            for(let i = 0; i < graph.edges.length; i++){
                if(graph.edges[i].src == edge.src && graph.edges[i].dst != edge.dst){
                    graph.edges[i].type = "fallthrough"
                }
            }
        }
        if(edge.type == "fallthrough"){
            color = 'red';
        }
        return {
            id: `edge-${index}`,
            source: edge.src.toString(),
            target: edge.dst.toString(),
            type: 'smoothstep',
            markerEnd: {
                type: MarkerType.ArrowClosed,
                color: color,
            },
            style: { stroke: color, strokeWidth: 2 }
        }
    });

    //return await layoutGraph(nodes, edges, nodeSizes);
    return {nodes, edges};
};


export default function Graph() {
    const [analysisContext] = useContext(AnalysisContext);
    const {nodeSizes} = useContext(NodeSizeContext);
    const [graph, setGraph] = useState(null);
    const [nodes, setNodes, onNodesChange] = useNodesState([]);
    const [edges, setEdges, onEdgesChange] = useEdgesState([]);
    const [error, setError] = useState();

    useEffect(() => {
        if (analysisContext.graphSet) {
            convertToReactFlowFormat(analysisContext.graph, nodeSizes).then(convertedGraph => {
                setGraph(convertedGraph);
                setEdges(convertedGraph.edges);

                const disasmRequests = convertedGraph.nodes.map(node =>
                    axios.post(`${import.meta.env.VITE_BACKEND}api/disasms/`, { "block_id": node.id })
                );

                Promise.all(disasmRequests)
                    .then(responses => {
                        let updatedNodes = convertedGraph.nodes.map((node, index) => {
                            const disasmData = responses[index].data;
                            let text = [];
                            for (let j = 0; j < disasmData.length; j++) {
                                text.push({ "addr": disasmData[j].addr, "op": disasmData[j].op, "data": disasmData[j].data });
                            }
                            return {
                                ...node,
                                data: { label: node.id, text }
                            };
                        });
                        updatedNodes = updatedNodes.filter(node => node.data.text.length > 0);
                        setNodes(updatedNodes);
                        setError();
                    }).then(() => {
                        // console.log("AFTER FIRST UPDATE")
                    })
                    .catch(error => {
                        console.error("Error fetching disassemblies:", error);
                        setError(`Error fetching disassemblies: ${error}`)
                    });
            });
        }
    }, [analysisContext.graph]);

    useEffect(() => {
        async function run() {
            if(Object.keys(nodeSizes).length != 0){
                const result = await layoutGraph(nodes, edges, nodeSizes);
                setNodes(result.nodes);
                setEdges(result.edges);
            }
        }
        run()
    }, [nodeSizes])

    if (!graph) {
        return (
        <div className="component-wrapper font-xs text-mono">
            <div className="component-body">
                <div className="text-xs font-mono">No function selected</div>
            </div>
        </div>
        );
    }

    return (
        <div className="component-wrapper font-xs text-mono">
            {error && (<span>{error}</span>)}
                <ReactFlowProvider>
                    <ReactFlow
                        nodes={nodes}
                        edges={edges}
                        onNodesChange={onNodesChange}
                        // onEdgesChange={onEdgesChange}
                        nodeTypes={nodeTypes}
                        minZoom={0.05}
                        nodesConnectable={false}
                        fitView
                    >
                        <Controls />
                        <Background />
                    </ReactFlow>
                </ReactFlowProvider>
        </div>
    );
}
