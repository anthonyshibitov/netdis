import './NavBar.css';
import { Link } from "react-router-dom";

export default function NavBar() {
    return (
        <ul className="navbar-container">
            <li>
                <Link to="/">Home</Link>
            </li>
            <li>
                <Link to="/info">Info</Link>
            </li>
            <li>Login</li>
            <li>
                <Link to="/upload">Upload</Link>
            </li>

        </ul>
    )
}