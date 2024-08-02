import { useContext, useState, useEffect } from "react";
import { AnalysisContext } from "../context/AnalysisContext";
import axios from "axios";
import './Listing.css'

export default function Listing() {
    const [analysisContext, setAnalysisContext] = useContext(AnalysisContext);
    const [f, setF] = useState("No function selected");
    const [blocks, setBlocks] = useState([]);

    useEffect(() => {

    }, [])

    function addressClick(address){
        const i = internalFuncRef(address).index;
        if(i != false){
            if(analysisContext.func_history){
                const newFuncHistory = [...analysisContext.func_history, analysisContext.all_functions[i].id]
                setAnalysisContext({...analysisContext, func_history: newFuncHistory, selected_function: analysisContext.all_functions[i].id})
            } else {
                setAnalysisContext({...analysisContext, func_history: [id], selected_function: analysisContext.all_functions[i].id})
            }
        }
    }

    function internalFuncRef(address){
        const regex = /^[0-9A-Fa-f]+h$/;
        if(address.match(regex)){
            const numFunctions = analysisContext.all_functions.length;
            const trimmedAddress = address.replace(/h$/, '');
            for(let i = 0; i < numFunctions; i++ ){
                let currentFuncAddr = analysisContext.all_functions[i].addr;
                currentFuncAddr = currentFuncAddr.replace(/^0x/, '');
                if(currentFuncAddr == trimmedAddress){
                    return {index: i, name: analysisContext.all_functions[i].name};
                }
            }
        }
        return false;
    }

    // function addressHover(address){
    //     const regex = /^[0-9A-Fa-f]+h$/;
    //     if(address.match(regex)){
    //         const numFunctions = analysisContext.all_functions.length;
    //         const trimmedAddress = address.replace(/h$/, '');
    //         for(let i = 0; i < numFunctions; i++ ){
    //             let currentFuncAddr = analysisContext.all_functions[i].addr;
    //             currentFuncAddr = currentFuncAddr.replace(/^0x/, '');
    //             if(currentFuncAddr == trimmedAddress){
    //                 break;
    //             }
    //         }
    //     }
    // }

    useEffect(() => {
        if (analysisContext.selected_function != null) {
            setF(`Selected function: ${analysisContext.selected_function}`);

            const url = import.meta.env.VITE_BACKEND + 'api/blocks/';
            axios.post(url, { "function_id": analysisContext.selected_function }).then(response => {
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
    }, [analysisContext]);

    return (
        <div className="component-wrapper listing-wrapper">
            <div className="component-title">Disassembly: {analysisContext.func_banner}</div>
            <div className="component-body listing-container">
                {blocks.map((block, key) => (
                    <div key={key} className="listing-block">
                        <div className="listing-label">LABEL {block.addr}</div>
                        {block.disassembly.map((d, dkey) => (
                            <div className="listing-line" key={dkey}>
                                <span className="listing-addr">
                                    {d.addr}:
                                </span>
                                <span className="listing-op">
                                    {d.op}&nbsp;
                                </span>
                                <span onClick={() => addressClick(d.data)} className="listing-data">
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