import { useContext, useState, useEffect } from "react";
import { AnalysisContext } from "../context/AnalysisContext";
import axios from "axios";
// import './Listing.css'

export default function Listing() {
    const [analysisContext, setAnalysisContext] = useContext(AnalysisContext);
    const [blocks, setBlocks] = useState([]);

    function addressClick(address){
        const i = internalFuncRef(address).index;
        console.log
        if(i != false){
            if(analysisContext.funcHistory){
                const newFuncHistory = [...analysisContext.funcHistory, analysisContext.allFunctions[i].id]
                setAnalysisContext({...analysisContext, funcHistory: newFuncHistory, selectedFunction: analysisContext.allFunctions[i].id})
            } else {
                setAnalysisContext({...analysisContext, funcHistory: [id], selectedFunction: analysisContext.allFunctions[i].id})
            }
        }
    }

    function internalFuncRef(address){
        const regex = /^[0-9A-Fa-f]+h$/;
        if(address.match(regex)){
            const numFunctions = analysisContext.allFunctions.length;
            const trimmedAddress = address.replace(/h$/, '');
            for(let i = 0; i < numFunctions; i++ ){
                let currentFuncAddr = analysisContext.allFunctions[i].addr;
                currentFuncAddr = currentFuncAddr.replace(/^0x/, '');
                if(currentFuncAddr == trimmedAddress){
                    return {index: i, name: analysisContext.allFunctions[i].name};
                }
            }
        }
        return false;
    }

    useEffect(() => {
        if (analysisContext.selectedFunction != null) {
            const url = import.meta.env.VITE_BACKEND + 'api/blocks/';
            axios.post(url, { "function_id": analysisContext.selectedFunction }).then(response => {
                const fetchedBlocks = response.data;

                const disasmPromises = fetchedBlocks.map(block => {
                    const disasmUrl = import.meta.env.VITE_BACKEND + 'api/disasms/';
                    return axios.post(disasmUrl, { "block_id": block.id }).then(disasmResponse => {
                        return {
                            blockId: block.id,
                            disassembly: disasmResponse.data
                        };
                    }).catch(error => {
                        console.log("Error fetching disasms:", error);
                        return {
                            blockId: block.id,
                            disassembly: []
                        };
                    });
                });

                Promise.all(disasmPromises).then(disasmResults => {
                    const blocksWithDisasm = fetchedBlocks.map(block => {
                        const disasmForBlock = disasmResults.find(disasm => disasm.blockId === block.id);
                        return {
                            ...block,
                            disassembly: disasmForBlock ? disasmForBlock.disassembly : []
                        };
                    });
                    setBlocks(blocksWithDisasm);
                });
            }).catch(error => {
                console.error("Error fetching blocks:", error);
            });
        }
    }, [analysisContext.selectedFunction]);

    return (
        <div className="component-wrapper">
            <div className="component-body font-mono">
                {blocks.map((block, key) => (
                    <div key={key} className="text-xs">
                        <div className="overflow-x-auto text-black/75 p-0">--> LABEL {block.addr}</div>
                        {block.disassembly.map((d, dkey) => (
                            <div className="flex flex-nowrap whitespace-nowrap" key={dkey}>
                                <span className="text-purple-900">
                                    {d.addr}:&nbsp;
                                </span>
                                <span className="text-blue-800">
                                    {d.op}&nbsp;
                                </span>
                                <span onClick={() => addressClick(d.data)} className="text-red-800">
                                    {d.data}
                                </span>
                                <span className="xref">{internalFuncRef(d.data) ? `[XREF=>${internalFuncRef(d.data).name}]` : ''}</span>
                            </div>
                        ))}
                    </div>
                ))}
            </div>
        </div>
    );
}