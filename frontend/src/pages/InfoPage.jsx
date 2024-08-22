import React, { useState } from 'react';
import NavBar from '../components/NavBar';
import Upload from '../components/Upload';

export default function InfoPage() {
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
                    </div>
                    <div className="text-2xl font-bold">
                        About
                    </div>
                    <div className="max-w-lg flex flex-col items-center gap-5">
                        <p>
                            Netdis is an online disassembler which uses Ghidra. It currently offers disassembly, decompilation, and function control flow graphing, with more features planned. If you'd like to contribute to the project, please visit the <a className="underline text-blue-600 hover:text-blue-800 visited:text-purple-600" href="https://github.com/anthonyshibitov/netdis" target="_blank" rel="noopener noreferrer">github repo link!</a> Any and all contributions are welcome :)
                        </p>
                    </div>
                    <div className="text-2xl font-bold">
                        Donations
                    </div>
                    <div className="max-w-lg">
                        I'm currently running this on a server out of pocket. There are no paid features, advertising, or sponsorships supporting this project. If you'd like to toss me a couple bucks, considering donating via my Ko-fi. Your support will be greatly appreciated, and will go directly to paying server costs/possible upgrading to increase analysis speeds! (don't worry, the widget doesn't show up on the analysis page)
                    </div>
                    <div>
                    <a href='https://ko-fi.com/E1E5123B6L' target='_blank'><img height='36' style={{border: "0px", height: "36px"}} src='https://storage.ko-fi.com/cdn/kofi5.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>
                    </div>
                    <div></div>
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