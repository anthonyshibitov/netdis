import './HomePage.css';
import NavBar from '../components/NavBar';

export default function HomePage() {
    return (
        <div className="main-container">
            <NavBar />
            <div className="logo">
            <span className="blue">net</span><span className="grey">dis</span>
            </div>
        </div>
    )
}