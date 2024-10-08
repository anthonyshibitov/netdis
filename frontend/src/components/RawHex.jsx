import { useState, useEffect, useRef, useCallback } from "react";
import axios from "axios";

export default function RawHex(props) {
    const file_id = props.rawhexProps.file_id;
    const image_base = props.rawhexProps.image_base;
    const [address, setAddress] = useState(image_base);
    const [allData, setAllData] = useState({});
    const [error, setError] = useState();
    const [isLoading, setIsLoading] = useState(false);
    const [hasMore, setHasMore] = useState(true);
    const containerRef = useRef(null);
    const observerRef = useRef(null);

    const FETCH_SIZE = 512; // Set fetch size to 512 bytes

    const lastElementRef = useCallback(node => {
        if (isLoading) return;
        if (observerRef.current) observerRef.current.disconnect();
        observerRef.current = new IntersectionObserver(entries => {
            if (entries[0].isIntersecting && hasMore) {
                const lastAddress = Object.keys(allData).pop();
                if (lastAddress) {
                    fetchData(lastAddress);
                }
            }
        });
        if (node) observerRef.current.observe(node);
    }, [isLoading, hasMore, allData]);

    useEffect(() => {
        fetchData(image_base);
    }, []);

    const sendAddressRequest = (e) => {
        e.preventDefault();
        const newAddress = parseInt(address, 16);
        if (isNaN(newAddress) || newAddress < image_base) {
            setError("Invalid address. Please enter a valid hexadecimal address at or above the image base.");
            console.log("fucked")
            return;
        }
        console.log("not fucked")
        setHasMore(true);
        setError();
        setAllData({}); // Clear existing data
        fetchData(newAddress);
    };

    const fetchData = (startAddress) => {
        if (isLoading || !hasMore) {
            console.log("fukcky return")
            return;
        }
        setIsLoading(true);
        const url = import.meta.env.VITE_BACKEND + 'api/rawhex/';
        axios.post(url, { 
            "file_id": file_id, 
            "address": startAddress.toString(16), 
            "length": FETCH_SIZE.toString() 
        })
        .then(response => {
            const task_id = response.data.task_id;
            const timer = setInterval(() => {
                const url = import.meta.env.VITE_BACKEND + "api/task/" + task_id;
                axios.get(url).then((response) => {
                    if(response.data.status == "DONE" && response.data.task_type == "raw_request"){
                        let result = JSON.parse(response.data.result.rawhex.replace(/'/g, '"'));
                        setAllData(prevData => ({...prevData, ...result}));
                        setError(null);
                        setIsLoading(false);
                        setHasMore(Object.keys(result).length === FETCH_SIZE);
                        clearInterval(timer);
                    }
                    if(response.data.status == "DONE" && response.data.task_type == "error"){
                        let result = JSON.parse(response.data.result.error.replace(/'/g, '"'));
                        console.log(result.error)
                        setError(result.error);
                        setIsLoading(false);
                        setHasMore(false);
                        clearInterval(timer);
                    }
                });
            }, 1000);
        })
        .catch(error => {
            console.error("Error fetching data:", error);
            setError("Failed to fetch data. Please try again.");
            setIsLoading(false);
        });
    };

    function handleChange(event){
        const newAddress = event.target.value;
        setAddress(newAddress);
    }

    return (
        <div className="text-xs font-mono flex flex-col component-wrapper p-1">
            <form className="flex items-center" onSubmit={sendAddressRequest}>
                <span className="px-1">Addr</span>
                <input 
                    className="grow border border-black min-w-0" 
                    type="text" 
                    value={address}
                    onChange={(e) => setAddress(e.target.value)}
                    onFocus={e => e.target.select()} 
                />
                <button 
                    type="submit" 
                    className="grow-0 px-1 border-2 bg-ndblue text-white"
                >
                    View
                </button>
            </form>
            <div ref={containerRef} className="">
                {Object.entries(allData).map(([address, value], i, arr) => (
                    <span key={i} ref={i === arr.length - 1 ? lastElementRef : null}>
                        {i % 8 === 0 && <span className="text-ndblue">&#10;&#13;{address}:&nbsp;</span>}
                        <span className={value === "??" ? "bg-red-300" : ""}>{value}&nbsp;</span>
                    </span>
                ))}
                {isLoading && <div>Loading...</div>}
                {error && <div className="p-1">{error}</div>}
            </div>
        </div>
    )
}