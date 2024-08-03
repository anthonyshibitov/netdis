import './NavBar.css';
import { Link } from "react-router-dom";

export default function NavBar({ onUploadClick }) {
    return (
        <div className="bg-white flex justify-between py-4 px-16 shadow sticky top-0">
            <Link to="/" className="text-2xl">
                        <span className="text-ndblue">net</span><span className="text-ndgrey">dis</span>
                </Link>
            <ul className="flex items-center gap-16">
                <li>
                    <button className="p-2 rounded-md hover:ring-2" onClick={onUploadClick}>Upload</button>
                </li>
                <li>
                    <Link to="/info" className="p-2 rounded-md hover:ring-2">Info</Link>
                </li>
            </ul>
        </div>
    )
}