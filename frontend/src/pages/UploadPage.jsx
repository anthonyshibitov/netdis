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
        setStatus("Uploading...")
        console.log(`Uploading to ${url}...`)
        axios.post(url, formData, config).then((response) => {
            setHash(response.data.hash);
            setProject_id(response.data.project_id);
            setStatus(`Received hash: ${response.data.hash}`);
            console.log(`Received hash: ${response.data.hash}`)
            const url = `${import.meta.env.VITE_BACKEND}api/funcs/`;
            return axios.post(url, {"project_id": response.data.project_id});
        }).then((response) => {
            state = response.data;
        }).then(() => {
            navigate("/analysis", { state });
        })
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