import { useState, useContext, useEffect, useRef } from "react";
import axios from "axios";
import { AnalysisContext } from "../context/AnalysisContext";


export default function FunctionList(props) {
    const funcs = props.functionListProps.funcs;
    const file_id = props.functionListProps.file_id;
    const [dis, setDis] = useState([]);
    const [analysisContext, setAnalysisContext] = useContext(AnalysisContext);

    useEffect(() => {
        setAnalysisContext({...analysisContext, allFunctions: props.funcs, funcHistory: []})
    }, []);

    useEffect(() => {
        console.log(analysisContext.funcHistory)
    }, [analysisContext.funcHistory]);

    useEffect(() => {
        if (analysisContext.selectedFunction !== null) {

            const index = funcs.findIndex(f => f.id === analysisContext.selectedFunction);
            if (index !== -1 && scrollRefs.current[index]) {
                scrollRefs.current[index].scrollIntoView({ behavior: 'smooth'});
            }
            console.log("BANNER CODE")
            console.log(funcs[index])
            //setAnalysisContext({...analysisContext, funcBanner: `${funcs[index].name}`})
        }
    }, [analysisContext.selectedFunction]);

    function onBackClick(){
        if(analysisContext.funcHistory.length > 1){
            const funcHistory = analysisContext.funcHistory.slice(0, -1);
            setAnalysisContext({...analysisContext, selectedFunction: funcHistory[funcHistory.length - 1], funcHistory: funcHistory})
        }
    }

    const scrollRefs = useRef([]);

    async function onFunctionClick(id){        
        if(analysisContext.funcHistory){
            const newFuncHistory = [...analysisContext.funcHistory, id]
            setAnalysisContext({...analysisContext, funcHistory: newFuncHistory, selectedFunction: id})
        } else {
            setAnalysisContext({...analysisContext, funcHistory: [id], selectedFunction: id})
        }
    }

    function cfg_req(func_id){
        const url = import.meta.env.VITE_BACKEND + 'api/func_graph/';
        axios.post(url, { "file_id": file_id, "function_id": func_id })
        .then(response => {
            const task_id = response.data.task_id;
            const timer = setInterval(() => {
                const url = import.meta.env.VITE_BACKEND + "api/task/" + task_id;
                const resp = axios.get(url).then((response => {
                    console.log(response);
                    if(response.data.status == "DONE" && response.data.task_type == "cfg_analysis"){
                        clearInterval(timer);
                        const graph = response.data.result.json_result;
                        console.log("GOT GRAPH")
                        console.log(graph)
                        setAnalysisContext({...analysisContext, graph: graph, graphSet: true})
                    }
                }))
            }, 1000);
        })
    }

    function decomp_req(func_id){
        const url = import.meta.env.VITE_BACKEND + 'api/decomp_func/';
        axios.post(url, { "file_id": file_id, "function_id": func_id })
        .then(response => {
            const task_id = response.data.task_id;
            const timer = setInterval(() => {
                const url = import.meta.env.VITE_BACKEND + "api/task/" + task_id;
                const resp = axios.get(url).then((response => {
                    console.log(response);
                    if(response.data.status == "DONE" && response.data.task_type == "decomp_func"){
                        clearInterval(timer);
                        const decomp_result = response.data.result.decomp_result;
                        setAnalysisContext({...analysisContext, decomp: decomp_result})
                        console.log(decomp_result)
                    }
                }))
            }, 1000);
        })
    }

    return (
        <div className="component-wrapper">
            <div className="component-title"><button onClick={onBackClick}>Back</button></div>
            <div className="component-body font-mono text-xs">
                {funcs.map((f,index) => {
                return (
                    <div key={f.id} ref={el => scrollRefs.current[index] = el} className={"function-item " + (analysisContext.selectedFunction == f.id ? 'function-highlight' : '')} onClick={() => onFunctionClick(f.id)}>
                        {f.addr}:{f.name}
                        &nbsp;<button className="text-ndblue" onClick={() => cfg_req(f.id)}>&lt;CFG&gt;</button>
                        &nbsp;<button className="text-ndblue" onClick={() => decomp_req(f.id)}>&lt;DECOMP&gt;</button>
                    </div>
                )})}
            </div>
        </div>
    )
}