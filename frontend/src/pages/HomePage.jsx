import React, { useState } from 'react';
import NavBar from '../components/NavBar';
import Upload from '../components/Upload';

export default function HomePage() {
    console.log(import.meta.env.VITE_BACKEND);
    const [showModal, setShowModal] = useState(false);

    function toggleModal(){
        const current = showModal;
        setShowModal(!current);
    }

    return (
        <div>
            <NavBar onUploadClick={toggleModal}/>
            <div className="overflow-x-hidden flex justify-center pt-16">
                <div className="flex flex-col justify-center items-center gap-20">
                    <div className="flex flex-col justify-center items-center gap-6">
                        <p className="text-8xl font-medium"><span className="text-ndblue">net</span><span className="text-ndgrey">dis</span> web disassembler</p>
                        <div className="flex gap-4 items-center">
                                {/* <p className="text-s font-bold">Powered by:</p> */}
                                <img src="ghidra_logo.png" className="object-contain h-8 w-8" />
                                <img src="django_logo.png" className="object-contain h-8 w-16" />
                        </div>
                    </div>
                    <div className="shadow-xl w-screen bg-cover h-96 flex flex-row justify-center items-center gap-16 bg-[url('/graph_skew_dark.png')] text-xl text-white">
                        <div className="w-96 text-justify drop-shadow-[0_1.2px_1.2px_rgba(0,0,0,0.8)]">
                            netdis is an online and open-source binary analysis platform based on the Ghidra suite of tools. simply upload a file and analyze it - all within your browser.
                        </div>
                        <div className="w-96 text-justify drop-shadow-[0_1.2px_1.2px_rgba(0,0,0,0.8)]">
                            <p>netdis supports full binary disassembly, decompilation, and function control flow graph recovery. many features upcoming, stay tuned 🕵️‍♂️</p>
                        </div>
                    </div>
                    <div className="">
                        <button className="text-xl px-6 py-3 text-white bg-ndblue rounded-md hover:ring-2" onClick={toggleModal}>Upload</button>
                    </div>
                    <div className="flex flex-row gap-8 justify-center">
                        <p>Like what you see? Have suggestions? Is my code unbearably bad? Fork this repo!</p>
                        <iframe src="https://ghbtns.com/github-btn.html?user=anthonyshibitov&repo=netdis&type=fork&count=true&size=large" frameBorder="0" scrolling="0" width="170" height="30" title="GitHub"></iframe>
                    </div>
                    <a className="mb-32" href='https://ko-fi.com/E1E5123B6L' target='_blank'><img height='36' style={{border: "0px", height: "36px"}} src='https://storage.ko-fi.com/cdn/kofi5.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>
                </div>
            </div>

            {showModal && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center">
                    <div className="bg-white p-4 rounded flex flex-col">
                        <Upload />
                        <button 
                            className="mt-4 text-red-500"
                            onClick={toggleModal}
                        >
                            Cancel
                        </button>
                    </div>
                </div>
            )}
        </div>
    )
}