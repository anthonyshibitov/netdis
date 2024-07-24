import { useState, useContext } from "react";
import axios from "axios";
import './FunctionList.css';
import { AnalysisContext } from "../context/AnalysisContext";

export default function FunctionList(props) {
    const [func, setFunc] = useState([]);
    const funcs = props.funcs;
    const [dis, setDis] = useState([]);
    const [analysisContext, setAnalysisContext] = useContext(AnalysisContext);

    async function onFunctionClick(id){
        setAnalysisContext({selected_function: id});
        console.log(analysisContext);
        let resps = [];
        const url = import.meta.env.VITE_BACKEND + "api/blocks/";

        try {
            const response = await axios.post(url, { "function_id": id });
            const array = response.data.map(block => ({
                "addr": block.addr,
                "id": block.id
            }));
            setFunc(array);
        } catch (error) {
            console.error("Error fetching data:", error);
        }
    }
    return (
        <div className="function-list component-wrapper">
            <div className="component-title">Functions</div>
            <div className="component-body function-list-body">
                {funcs.map(f => {
                return (<div key={f.id} className={"function-item " + (analysisContext.selected_function == f.id ? 'function-highlight' : '')} onClick={() => onFunctionClick(f.id)}>{f.name}</div>)
                })}
            </div>
            selected function is {analysisContext.selected_function}
        </div>
    )
}