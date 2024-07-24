import { useContext, useState, useEffect } from "react";
import { AnalysisContext } from "../context/AnalysisContext";
import axios from "axios";
import './Listing.css'

export default function Listing() {
    const [analysisContext, setAnalysisContext] = useContext(AnalysisContext);
    const [f, setF] = useState("No function selected");
    const [blocks, setBlocks] = useState([]);
    const [disasm, setDisasm] = useState([]);

    useEffect(() => {
        if (analysisContext.selected_function != null) {
            setF(`Selected function: ${analysisContext.selected_function}`);

            const url = import.meta.env.VITE_BACKEND + 'api/blocks/';
            axios.post(url, { "function_id": analysisContext.selected_function }).then(response => {
                setBlocks(response.data);
                const blocks = response.data;

                const disasmPromises = blocks.map(block => {
                    const disasmUrl = import.meta.env.VITE_BACKEND + 'api/disasms/';
                    return axios.post(disasmUrl, { "block_id": block.id }).then(disasmResponse => {
                        return disasmResponse.data.map(d => `${d.addr}: ${d.op} ${d.data}`);
                    }).catch(error => {
                        console.log("Error fetching disasms:", error);
                    });
                });

                Promise.all(disasmPromises).then(disasmResults => {
                    // Flatten the array of arrays
                    const allDisasms = disasmResults.flat();
                    setDisasm(allDisasms);
                });
            }).catch(error => {
                console.error("Error fetching blocks:", error);
            });
        }
    }, [analysisContext]);

    return (
        <div className="listing-container">
            {blocks.map((block, key) => (
                <div key={key}>
                    LABEL {block.addr}
                </div>
            ))}
            {disasm.map((disasmItem, dkey) => (
                <div key={dkey}>
                    {disasmItem}
                </div>
            ))}
        </div>
    );
}
