import { useState } from "react";

export default function RawHex() {
    const [address, setAddress] = useState();
    function handleChange(event){
        const newAddress = event.target.value;
        setAddress(newAddress);
    }

    return (
        <div className="text-xs font-mono">
            <input className="border border-black" type="text" onChange={handleChange} />
            <button className="px-1 border-2 bg-ndblue text-white">View</button>
            {address}
        </div>
    )
}