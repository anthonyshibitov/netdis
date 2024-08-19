import React, { useState } from 'react';
import NavBar from '../components/NavBar';
import Upload from '../components/Upload';
import Kofi from '../components/Kofi';

export default function InfoPage() {
    console.log(import.meta.env.VITE_BACKEND);
    const [showModal, setShowModal] = useState(false);

    function toggleModal(){
        const current = showModal;
        setShowModal(!current);
    }

    return (
        <div>
            <Kofi />
            <NavBar onUploadClick={toggleModal}/>
            <div className="overflow-x-hidden flex justify-center pt-16">
                <div className="flex flex-col justify-center items-center gap-20">
                    <div className="flex flex-col justify-center items-center gap-6">
                        <p className="text-8xl font-medium"><span className="text-ndblue">net</span><span className="text-ndgrey">dis</span> web disassembler</p>
                    </div>
                    <div className="text-2xl font-bold">
                        About
                    </div>
                    <div className="max-w-lg">
                        Netdis is an online disassembler which uses Ghidra. It currently offers disassembly, decompilation, and function control flow graphing, with more features planned. If you'd like to contribute to the project, please visit the github repo link! Any and all contributions are welcome :)
                    </div>
                    <div className="text-2xl font-bold">
                        Donations
                    </div>
                    <div className="max-w-lg">
                        I'm currently running this on a server out of pocket. There are no paid features, advertising, or sponsorships supporting this project. If you'd like to toss me a couple bucks, there's a Ko-fi widget on the bottom left. Your support will be greatly appreciated!! (don't worry, the widget doesn't show up on the analysis page)
                    </div>
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