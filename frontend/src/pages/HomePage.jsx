import NavBar from '../components/NavBar';

export default function HomePage() {
    console.log(import.meta.env.VITE_BACKEND);
    return (
        <div>
            <div className="flex gap-4">
                <NavBar />
            </div>
            <div className="logo-placeholder-css">
                <span className="text-ndblue">net</span><span className="text-ndgrey">dis</span>
            </div>
        </div>
    )
}