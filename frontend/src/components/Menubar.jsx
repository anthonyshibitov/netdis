import { useContext, useState } from "react"
import './MenuBar.css';

export default function MenuBar() {
    
    return (
        <div className="border-b border-ndblue flex font-mono items-center text-xs font-bold bg-ccc h-5">
            <div className="px-4 pt-1 hover:bg-white">File</div>
            <div className="px-4 pt-1 hover:bg-white">Options</div>
            <div className="px-4 pt-1 hover:bg-white">Help</div>
        </div>
    )
}