import { useContext, useState, useEffect } from "react";
import { AnalysisContext } from "../context/AnalysisContext";
import axios from "axios";
import './Listing.css'

export default function Listing() {
    const [analysisContext, setAnalysisContext] = useContext(AnalysisContext);
    const [f, setF] = useState("No function selected");
    const [blocks, setBlocks] = useState([]);

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
        <div className="listing-container">
            {blocks.map((block, key) => (
                <div key={key} className="listing-label">
                    &emsp;&emsp;&emsp;LABEL {block.addr}
                    {block.disassembly.map((d, dkey) => (
                        <div key={dkey}>
                            <span className="listing-addr">{d.addr}</span>: 
                            {d.op} <span className="listing-instruction">{d.data}</span>
                        </div>
                    ))}
                </div>
            ))}
        </div>
    );
}