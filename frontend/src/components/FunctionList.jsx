import { useState, useContext, useEffect, useRef } from "react";
import axios from "axios";
import './FunctionList.css';
import { AnalysisContext } from "../context/AnalysisContext";


export default function FunctionList(props) {
    const funcs = props.funcs;
    const [dis, setDis] = useState([]);
    const [analysisContext, setAnalysisContext] = useContext(AnalysisContext);

    useEffect(() => {
        setAnalysisContext({...analysisContext, all_functions: props.funcs, func_history: []})
    }, []);

    useEffect(() => {
        console.log(analysisContext.func_history)
    }, [analysisContext.func_history]);

    useEffect(() => {
        if (analysisContext.selected_function !== null) {
            const index = funcs.findIndex(f => f.id === analysisContext.selected_function);
            if (index !== -1 && scrollRefs.current[index]) {
                scrollRefs.current[index].scrollIntoView({ behavior: 'smooth'});
            }
            setAnalysisContext({...analysisContext, func_banner: `${funcs[index].name}`})
        }
    }, [analysisContext.selected_function]);

    function onBackClick(){
        if(analysisContext.func_history.length > 1){
            const funcHistory = analysisContext.func_history.slice(0, -1);
            console.log("removed last", funcHistory);
            setAnalysisContext({...analysisContext, selected_function: funcHistory[funcHistory.length - 1], func_history: funcHistory})
        }
    }

    const scrollRefs = useRef([]);

    async function onFunctionClick(id){
        if(analysisContext.func_history){
            const newFuncHistory = [...analysisContext.func_history, id]
            setAnalysisContext({...analysisContext, func_history: newFuncHistory, selected_function: id})
        } else {
            setAnalysisContext({...analysisContext, func_history: [id], selected_function: id})
        }
    }
    return (
        <div className="function-list component-wrapper">
            <div className="component-title">Functions <button onClick={onBackClick}>Back</button></div>
            <div className="component-body function-list-body">
                {funcs.map((f,index) => {
                return (
                    <div key={f.id} ref={el => scrollRefs.current[index] = el} className={"function-item " + (analysisContext.selected_function == f.id ? 'function-highlight' : '')} onClick={() => onFunctionClick(f.id)}>
                        {f.addr}:{f.name}
                    </div>
                )
                })}
            </div>
        </div>
    )
}