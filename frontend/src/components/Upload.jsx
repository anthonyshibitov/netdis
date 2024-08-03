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
        axios.post(url, formData, config).then((response => {
            /* If project_id is null, it is still processing/queued! */
            if(response.data.project_id != null){
                console.log("THIS IS BAD")
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
                            console.log(response.data);
                            const file_id = response.data.object_id;
                            const url = `${import.meta.env.VITE_BACKEND}api/funcs/`;
                            axios.post(url, {"project_id": response.data.object_id}).then(response => {
                                navigate("/analysis", {state: {funcs: response.data, file_id: file_id}});
                            })
                        }
                    }))
                }, 1000);
            }
        }))
    }

    return (
        <>
            <form>
                <input type="file" onChange={handleChange}/>
            </form>
            <div>
                {status}
            </div>
        </>
    )
}