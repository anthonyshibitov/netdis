import { useState } from "react";
import axios from "axios";

export default function RawHex(props) {
    const file_id = props.rawhexProps.file_id;
    const [address, setAddress] = useState();
    const [data, setData] = useState();

    function handleChange(event){
        const newAddress = event.target.value;
        setAddress(newAddress);
    }

    function sendAddressRequest(){
        const url = import.meta.env.VITE_BACKEND + 'api/rawhex/';
        axios.post(url, { "file_id": file_id, "address": address, "length": 8 })
        .then(response => {
            const task_id = response.data.task_id;
            const timer = setInterval(() => {
                const url = import.meta.env.VITE_BACKEND + "api/task/" + task_id;
                const resp = axios.get(url).then((response => {
                    console.log(response);
                    if(response.data.status == "DONE" && response.data.task_type == "raw_request"){
                        console.log("DONE!")
                        let result = response.data.result.rawhex
                        setData(result);
                        result = result.replace(/'/g, '"');
                        result = JSON.parse(result)
                        clearInterval(timer);
                        console.log(result)
                    }
                }))
            }, 1000);
        })
    }

    return (
        <div className="text-xs font-mono">
            <input className="border border-black" type="text" onChange={handleChange} />
            <button className="px-1 border-2 bg-ndblue text-white" onClick={sendAddressRequest}>View</button>
            {data}
        </div>
    )
}