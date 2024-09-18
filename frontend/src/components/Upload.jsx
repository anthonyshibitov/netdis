import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

export default function UploadPage(props) {
    const [status, setStatus] = useState("");
    const navigate = useNavigate();
    const callbackFunction = props.callback;
    const [loaders, setLoaders] = useState();
    const [useLoaders, setUseLoaders] = useState(false);
    const [usingLoader, setUsingLoader] = useState();
    const [selectedLoader, setSelectedLoader] = useState("NONE");
    const [selectedLang, setSelectedLang] = useState("NONE");
    const [selectedFile, setSelectedFile] = useState();

    const handleFileChange = (e) => {
        setSelectedFile(e.target.files[0])
    }

    const handleLoaderCheckBox = () => {
        setUseLoaders(!useLoaders);
    }

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
                if(response.data.project_id != null){
                    console.log(response.data)
                    const file_id = response.data.file_id;
                    const url = `${import.meta.env.VITE_BACKEND}api/funcs/`;
                    axios.post(url, {"project_id": response.data.project_id}).then(response => {
                        callbackFunction ? callbackFunction(): '';
                        navigate("/analysis", {state: {funcs: response.data, file_id: file_id}, replace: true});
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
                                const file_id = response.data.result.project_id;
                                const url = `${import.meta.env.VITE_BACKEND}api/funcs/`;
                                axios.post(url, {"project_id": response.data.result.project_id}).then(response => {
                                    callbackFunction ? callbackFunction() : '';
                                    navigate("/analysis", {state: {funcs: response.data, file_id: file_id}, replace: true});
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
                        }))
                    }, 1000);
                }
            })).catch(error => {
                if(error.response.data.error){
                    setStatus(`ERROR: ${error.response.data.error} - ${error.response.data.error_info}`)
                    return;
                }
            })
        } else {
            const url = import.meta.env.VITE_BACKEND + "api/get_loaders/";
            let state;
            setStatus("Uploading...");
            axios.post(url, formData, config).then((response => {
                /* If project_id is null, it is still processing/queued! */
                if(response.data.project_id != null){
                    console.log(response.data)
                    const file_id = response.data.file_id;
                    const url = `${import.meta.env.VITE_BACKEND}api/funcs/`;
                    axios.post(url, {"project_id": response.data.project_id}).then(response => {
                        callbackFunction ? callbackFunction(): '';
                        navigate("/analysis", {state: {funcs: response.data, file_id: file_id}, replace: true});
                    })
                } else {
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
                }
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
            <label htmlFor="file-upload" className="cursor-pointer m-4 px-6 py-3 hover:ring-2 text-white bg-ndblue rounded-md">Select file</label>
            <input id="file-upload" type="file" className="hidden" onChange={handleFileChange}/>
            <div className="p-2 font-mono">
                {status}
            </div>
            <button onClick={uploadFile}>Upload</button>
            <div className="p-2 text-slate-400 italic text-xs">(2mb file upload limit)</div>
            <div className="pt-10 flex gap-2 items-center flex-col p-2">
                <div className="">Advanced options</div>
                <div className="flex items-center gap-2">
                    <input type="checkbox" name="useLoader" id="useLoader" onChange={handleLoaderCheckBox}/>
                    <label htmlFor="useLoader">Specify loader</label>
                </div>
                {loaders &&
                    <>
                        <select onChange={e => handleSelectedLoader(e.target.value)} name="loaders" id="loaders">
                        {Object.entries(loaders[0]).map(([name, string], key) => {
                            return (
                                <option key={key} value={string}>{name}-{string}</option>
                            )
                        })}
                        </select>
                        <select onChange={e => handleSelectedLang(e.target.value)} name="langs" id="langs">
                        {Object.entries(loaders[1]).map(([name, string], key) => {
                            return (
                                <option key={key} value={name}>{name}-{string}</option>
                            )
                        })}
                        </select>
                    </>
                }
            </div>
        </div>
    )
}