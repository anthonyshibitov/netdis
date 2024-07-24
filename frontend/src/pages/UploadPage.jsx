import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

export default function UploadPage() {
    const [file, setFile] = useState();
    const [status, setStatus] = useState("");
    const [hash, setHash] = useState("");
    const [project_id, setProject_id] = useState();
    const navigate = useNavigate();

    function handleChange(event){
        setFile(event.target.files[0]);
    }

    function handleSubmit(event){
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
        axios.post(url, formData, config).then((response => {
            /* If project_id is null, it is still processing/queued! */
            if(response.data.project_id != null){
                const url = `${import.meta.env.VITE_BACKEND}api/funcs/`;
                axios.post(url, {"project_id": response.data.project_id}).then(response => {
                    navigate("/analysis", {state: response.data});
                })
            } else {
                setStatus("File queued...");
                const task_id = response.data.id;
                const timer = setInterval(() => {
                    const url = import.meta.env.VITE_BACKEND + "api/task/" + task_id;
                    const resp = axios.get(url).then((response => {
                        console.log(response);
                        if(response.data.status == "DONE"){
                            clearInterval(timer);
                            const url = `${import.meta.env.VITE_BACKEND}api/funcs/`;
                            axios.post(url, {"project_id": response.data.project_id}).then(response => {
                                navigate("/analysis", {state: response.data});
                            })
                        }
                    }))
                }, 1000);
            }
        }))
    }

    return (
        <>
            <form onSubmit={handleSubmit}>
                <input type="file" onChange={handleChange}/>
                <button type="submit" >Upload</button>
            </form>
            <div>
                {status}
            </div>
        </>
    )
}