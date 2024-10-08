import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { useEffect } from "react";

export default function UploadPage(props) {
    const [status, setStatus] = useState("");
    const navigate = useNavigate();
    const callbackFunction = props.callback;
    const [loaders, setLoaders] = useState();
    const [useLoaders, setUseLoaders] = useState(false);
    const [showLoaderCheckbox, setShowLoaderCheckbox] = useState(true);
    const [usingLoader, setUsingLoader] = useState();
    const [selectedLoader, setSelectedLoader] = useState("NONE");
    const [selectedLang, setSelectedLang] = useState("NONE");
    const [selectedFile, setSelectedFile] = useState();
    const [uploadText, setUploadText] = useState("Analyze")

    const handleFileChange = (e) => {
        setSelectedFile(e.target.files[0])
    }

    const handleLoaderCheckBox = () => {
        setUseLoaders(!useLoaders);
        if(!useLoaders){
            setUploadText("Detect available specs");
        }
        if(useLoaders){
            setUploadText("Analyze");
        }
    }

    useEffect(() => {
        if (loaders) {
            const firstLoader = Object.entries(loaders[0])[0][1]; // Get the first loader value
            const firstLang = Object.entries(loaders[1])[0][0]; // Get the first language name
            setSelectedLoader(firstLoader);
            setSelectedLang(firstLang);
        }
    }, [loaders]);

    const handleSelectedLoader = (e) => {
        setSelectedLoader(e);
        console.log(e);
        console.log("selected loader", selectedLoader);
    }

    const handleSelectedLang = (e) => {
        setSelectedLang(e);
        console.log(e);
        console.log("selected lang", selectedLang);
    }

    function uploadFile(event){
        // const file = event.target.files[0];
        // event.preventDefault();
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('fileName', selectedFile.name);
        formData.append('loader', selectedLoader);
        formData.append('lang', selectedLang)
        let timeProcessing = 0;
        const config = {
            headers: {
                'content-type': 'multipart/form-data'
            }
        }
        if(!useLoaders){
            const url = import.meta.env.VITE_BACKEND + "api/binary_ingest/";
            let state;
            setStatus("Uploading...");
            axios.post(url, formData, config).then((response => {
                /* If project_id is null, it is still processing/queued! */
                if(response.data.file_id != null){
                    console.log("RECEIVED FROM UPLOAD PROCESSING...")
                    console.log(response.data)
                    const file_id = response.data.file_id;
                    const url = `${import.meta.env.VITE_BACKEND}api/funcs/`;
                    const image_base = response.data.image_base;
                    axios.post(url, {"file_id": response.data.file_id}).then(response => {
                        callbackFunction ? callbackFunction(): '';
                        navigate("/analysis", {state: {funcs: response.data, file_id: file_id, image_base: image_base}, replace: true});
                    })
                } else {
                    setStatus("File queued...");
                    const task_id = response.data.id;
                    const timer = setInterval(() => {
                        const url = import.meta.env.VITE_BACKEND + "api/task/" + task_id;
                        const resp = axios.get(url).then((response => {
                            console.log(response);
                            if(response.data.status == "DONE" && response.data.task_type == "file_upload"){
                                clearInterval(timer);
                                console.log("RECEIVED FROM UPLOAD PROCESSING...")
                                console.log(response.data)
                                const file_id = response.data.result.file_id;
                                const image_base = response.data.result.image_base;
                                const url = `${import.meta.env.VITE_BACKEND}api/funcs/`;
                                axios.post(url, {"file_id": response.data.result.file_id}).then(response => {
                                    console.log("funcs response")
                                    console.log(response.data)
                                    callbackFunction ? callbackFunction() : '';
                                    navigate("/analysis", {state: {funcs: response.data, file_id: file_id, image_base: image_base}, replace: true});
                                })
                            }
                            if(response.data.status == "PROCESSING"){
                                setStatus(`Processing. Time elapsed: ${timeProcessing}s`);
                                timeProcessing += 1;
                            }
                            if(response.data.status == "DONE" && response.data.task_type == "error"){
                                let result = response.data.result.error;
                                // Pesky single quotes!
                                result = result.replace(/'/g, '"');
                                result = JSON.parse(result)
                                clearInterval(timer)
                                setStatus(`ERROR: ${result.error}`)
                            }
                        })).catch(error => {
                            console.log(`new error ${error}`);
                        })
                    }, 1000);
                }
            })).catch(error => {
                console.log(error);
                // if(error.response.data.error){
                //     setStatus(`ERROR: ${error.response.data.error} - ${error.response.data.error_info}`)
                //     return;
                // }
                setStatus(`ERROR: ${error}`);
            })
        } else {
            const url = import.meta.env.VITE_BACKEND + "api/get_loaders/";
            let state;
            setStatus("Uploading...");
            axios.post(url, formData, config).then((response => {
                setStatus("Loading analyzers...");
                const task_id = response.data.id;
                const timer = setInterval(() => {
                    const url = import.meta.env.VITE_BACKEND + "api/task/" + task_id;
                    const resp = axios.get(url).then((response => {
                        console.log(response);
                        if(response.data.status == "DONE" && response.data.task_type == "loaders"){
                            clearInterval(timer);
                            console.log("GOT LOADERS")
                            console.log(response);
                            setStatus("Loaded analyzers.")
                            let loaders = response.data.result.loaders[1];

                            // Convert the object into an array of [key, value] pairs
                            let sortedLoadersArray = Object.entries(loaders).sort(([keyA], [keyB]) => keyA.localeCompare(keyB));

                            // Convert the sorted array back into an object
                            response.data.result.loaders[1] = Object.fromEntries(sortedLoadersArray);
                            setLoaders(response.data.result.loaders);
                            // To upload file normally..
                            // setUseLoaders(false);
                            // Hacky...
                            handleLoaderCheckBox();
                            setShowLoaderCheckbox(false);
                        }
                        if(response.data.status == "PROCESSING"){
                            setStatus(`Processing. Time elapsed: ${timeProcessing}s`);
                            timeProcessing += 1;
                        }
                        if(response.data.status == "DONE" && response.data.task_type == "error"){
                            let result = response.data.result.error;
                            // Pesky single quotes!
                            result = result.replace(/'/g, '"');
                            result = JSON.parse(result)
                            clearInterval(timer)
                            setStatus(`ERROR: ${result.error}`)
                        }
                    }))
                }, 1000);
            })).catch(error => {
                if(error.response.data.error){
                    setStatus(`ERROR: ${error.response.data.error} - ${error.response.data.error_info}`)
                    return;
                }
            })
        }
    }

    return (
        <div className="flex flex-col justify-center items-center p-4">
            <label htmlFor="file-upload" className="border-2 border-dashed border-slate-200 cursor-pointer m-4 px-8 py-8 hover:ring-2 text-black bg-slate-100 rounded-md">
                {!selectedFile ? (<>Select file</>) : (<>{selectedFile.name}</>)}
            </label>
            <input id="file-upload" type="file" className="hidden" onChange={handleFileChange}/>
            <div className="p-2 font-mono">
                {status}
            </div>
            <button className="cursor-pointer px-6 py-3 hover:ring-2 text-white bg-ndblue rounded-md" onClick={uploadFile}>{uploadText}</button>
            <div className="p-2 text-slate-400 italic text-xs">(2mb file upload limit)</div>
            <div className="pt-10 flex gap-2 items-center flex-col p-2">
                {showLoaderCheckbox && 
                <div>
                    <div className="">Advanced options</div>
                    <div className="flex items-center gap-2">
                        <input type="checkbox" name="useLoader" id="useLoader" onChange={handleLoaderCheckBox}/>
                        <label htmlFor="useLoader">Specify loader</label>
                    </div>
                </div>
                }
                {loaders &&
                    <>
                        <div>Select an appropriate loader and language</div>
                        <select className="w-full border-black border-2 rounded" onChange={e => handleSelectedLoader(e.target.value)} name="loaders" id="loaders" size="5">
                        {Object.entries(loaders[0]).map(([name, string], key) => {
                            return (
                                <option key={key} value={string}>{name}</option>
                            )
                        })}
                        </select>
                        <select className="w-full border-black border-2 rounded" onChange={e => handleSelectedLang(e.target.value)} name="langs" id="langs" size="10">
                        {Object.entries(loaders[1]).map(([name, string], key) => {
                            return (
                                <option key={key} value={name}>{name} - {string}</option>
                            )
                        })}
                        </select>
                    </>
                }
            </div>
        </div>
    )
}