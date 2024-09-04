import { useEffect, useState } from "react"
import axios from "axios";
import { jsx } from "react/jsx-runtime";

export default function Strings(props) {
    const file_id = props.stringsProps.file_id;
    const [error, setError] = useState();
    const [data, setData] = useState();

    useEffect(() => {
        const url = import.meta.env.VITE_BACKEND + 'api/strings/';
        axios.post(url, { "file_id": file_id })
        .then(response => {
            const task_id = response.data.task_id;
            const timer = setInterval(() => {
                const url = import.meta.env.VITE_BACKEND + "api/task/" + task_id;
                const resp = axios.get(url).then((response => {
                    console.log(response.data)
                    if(response.data.status == "DONE" && response.data.task_type == "strings"){
                        const result = response.data.result.strings
                        const jsxResult = Object.entries(result).map(([key, index]) => {
                            return (
                                <div key={index}><span className="text-ndblue">{key}</span>: {result[key]}</div>
                            )
                        })
                        setData(jsxResult);
                        setError();
                        clearInterval(timer);   
                    }
                    if(response.data.status == "DONE" && response.data.task_type == "error"){
                        const result = response.data.result.error
                        setError(result.error);
                        setData();
                        clearInterval(timer);                        
                    }
                }))
            }, 1000);
        })
    }, [])

    return (
        <div className="component-wrapper font-mono text-xs">
            <div>{data}</div>
            <div>{error}</div>
        </div>
    )
}