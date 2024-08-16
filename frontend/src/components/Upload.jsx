import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

export default function UploadPage() {
    const [status, setStatus] = useState("");
    const navigate = useNavigate();

    function handleChange(event){
        const file = event.target.files[0];
        event.preventDefault();
        const url = import.meta.env.VITE_BACKEND + "api/binary_ingest/";
        const formData = new FormData();
        formData.append('file', file);
        formData.append('fileName', file.name);
        const config = {
            headers: {
                'content-type': 'multipart/form-data'
            }
        }
        let state;
        setStatus("Uploading...");
        console.log("URL")
        console.log(url)
        axios.post(url, formData, config).then((response => {
            /* If project_id is null, it is still processing/queued! */
            if(response.data.project_id != null){
                console.log(response.data)
                const file_id = response.data.file_id;
                const url = `${import.meta.env.VITE_BACKEND}api/funcs/`;
                axios.post(url, {"project_id": response.data.project_id}).then(response => {
                    navigate("/analysis", {state: {funcs: response.data, file_id: file_id}});
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
                            console.log("DONE API RESPONSE")
                            console.log("Response data for task id", task_id)
                            console.log(response.data);
                            const file_id = response.data.result.project_id;
                            console.log("Uploaded project id..", file_id)
                            const url = `${import.meta.env.VITE_BACKEND}api/funcs/`;
                            axios.post(url, {"project_id": response.data.result.project_id}).then(response => {
                                console.log("DONE FUNCS API RESPONSE")
                                console.log("Response data for project id")
                                console.log(response.data)
                                navigate("/analysis", {state: {funcs: response.data, file_id: file_id}});
                            })
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
            console.log("ERROR!!");
            console.log(error.response.data);
            if(error.response.data.error){
                console.log("ERROR");
                console.log(error.response.data.error);
                setStatus(`ERROR: ${error.response.data.error} - ${error.response.data.error_info}`)
                return;
            }
        })
    }

    return (
        <div className="flex flex-col justify-center items-center p-4">
            <label htmlFor="file-upload" className="cursor-pointer m-4 px-6 py-3 hover:ring-2 text-white bg-ndblue rounded-md">Select file</label>
            <input id="file-upload" type="file" className="hidden" onChange={handleChange}/>
            <div className="p-2">
                {status}
            </div>
        </div>
    )
}