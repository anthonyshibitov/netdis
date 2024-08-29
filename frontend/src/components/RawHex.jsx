import { useState } from "react";
import axios from "axios";

export default function RawHex(props) {
    const file_id = props.rawhexProps.file_id;
    const [address, setAddress] = useState();
    const [size, setSize] = useState("1");
    const [data, setData] = useState();
    function handleChange(event){
        const newAddress = event.target.value;
        setAddress(newAddress);
    }

    function sendAddressRequest(){
        const url = import.meta.env.VITE_BACKEND + 'api/rawhex/';
        axios.post(url, { "file_id": file_id, "address": address, "length": size })
        .then(response => {
            const task_id = response.data.task_id;
            const timer = setInterval(() => {
                const url = import.meta.env.VITE_BACKEND + "api/task/" + task_id;
                const resp = axios.get(url).then((response => {
                    if(response.data.status == "DONE" && response.data.task_type == "raw_request"){
                        let result = response.data.result.rawhex
                        result = result.replace(/'/g, '"');
                        result = JSON.parse(result)
                        setData(result);
                        clearInterval(timer);                        
                    }
                }))
            }, 1000);
        })
    }

    return (
        <div className="text-xs font-mono flex flex-col component-wrapper">
            <div className="flex">
                <input className="grow border border-black" type="text" onChange={handleChange} />
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
                <button className="grow-0 px-1 border-2 bg-ndblue text-white" onClick={sendAddressRequest}>View</button>
            </div>
            <div className="">
                {data && 
                    Object.entries(data).map(([address, value], i) => (
                        <span>
                            {i % 8 === 0 && <span>&#10;&#13;{address}:&nbsp;</span>}
                            <span>{value}&nbsp;</span>
                        </span>
                    ))
                }
            </div>
        </div>
    )
}