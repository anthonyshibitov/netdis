import { useState } from "react";
import axios from "axios";

export default function RawHex(props) {
    const file_id = props.rawhexProps.file_id;
    const [address, setAddress] = useState();
    const [size, setSize] = useState("1");
    const [data, setData] = useState();
    const [error, setError] = useState();
    function handleChange(event){
        const newAddress = event.target.value;
        setAddress(newAddress);
    }

    function sendAddressRequest(e){
        e.preventDefault();
        const url = import.meta.env.VITE_BACKEND + 'api/rawhex/';
        axios.post(url, { "file_id": file_id, "address": address, "length": size })
        .then(response => {
            const task_id = response.data.task_id;
            const timer = setInterval(() => {
                const url = import.meta.env.VITE_BACKEND + "api/task/" + task_id;
                const resp = axios.get(url).then((response => {
                    console.log(response.data)
                    if(response.data.status == "DONE" && response.data.task_type == "raw_request"){
                        let result = response.data.result.rawhex
                        result = result.replace(/'/g, '"');
                        result = JSON.parse(result)
                        setData(result);
                        setError();
                        clearInterval(timer);                        
                    }
                    if(response.data.status == "DONE" && response.data.task_type == "error"){
                        let result = response.data.result.error
                        result = result.replace(/'/g, '"');
                        result = JSON.parse(result)
                        setError(result.error);
                        setData();
                        clearInterval(timer);                        
                    }
                }))
            }, 1000);
        })
    }

    return (
        <div className="text-xs font-mono flex flex-col component-wrapper p-1">
            <form className="flex items-center" onSubmit={(e => sendAddressRequest(e))}>
                <span className="px-1">Addr</span>
                <input className="grow border border-black min-w-0" type="text" onChange={handleChange} onFocus={e => e.target.select()} />
                <span className="px-1">Size</span>
                <select name="size" id="size" onChange={e => setSize(e.target.value)} value={size}>
                    <option value="1">1</option>
                    <option value="2">2</option>
                    <option value="4">4</option>
                    <option value="8">8</option>
                    <option value="16">16</option>
                    <option value="32">32</option>
                    <option value="64">64</option>
                    <option value="128">128</option>

                </select>
                <button type="submit" className="grow-0 px-1 border-2 bg-ndblue text-white" onClick={( e => sendAddressRequest(e))}>View</button>
            </form>
            <div className="">
                {data && 
                    Object.entries(data).map(([address, value], i) => (
                        <span key={i}>
                            {i % 8 === 0 && <span className="text-ndblue">&#10;&#13;{address}:&nbsp;</span>}
                            <span className={value === "??" ? "bg-red-300" : ""}>{value}&nbsp;</span>
                        </span>
                    ))
                }
                {error && (
                    <div className="p-1">{error}</div>
                )}
            </div>
        </div>
    )
}