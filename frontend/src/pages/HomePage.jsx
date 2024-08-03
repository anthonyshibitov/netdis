import NavBar from '../components/NavBar';

export default function HomePage() {
    console.log(import.meta.env.VITE_BACKEND);
    return (
        <div>
            <div className="">
                <NavBar />
            </div>
            <div className="flex justify-center pt-16">
                <div className="flex flex-col justify-center items-center gap-20">
                    <p className="text-7xl font-medium"><span className="text-ndblue">net</span><span className="text-ndgrey">dis</span> web disassembler 🧑‍💻</p>
                    <div className="flex gap-4 items-center">
                            <p className="text-s font-bold">Powered by:</p>
                            <img src="ghidra_logo.png" className="object-contain h-8 w-8" />
                            <img src="django_logo.png" className="object-contain h-8 w-16" />
                        </div>
                    <div className="shadow-xl w-screen bg-cover h-96 flex flex-row justify-center items-center gap-16 bg-[url('/graph_skew_dark.png')]">
                        <p className="w-96 text-justify text-xl text-white drop-shadow-[0_1.2px_1.2px_rgba(0,0,0,0.8)]">netdis is an online and open-sourced binary analysis platform based on the Ghidra suite of tools. simply upload a file and analyze it.</p>
                    </div>
                    <div className="flex flex-col justify-center items-start">
                        <p>Current features ⚡️</p>
                        <p> - Full binary analysis</p>
                        <p> - Function control flow graphing</p>
                    </div>
                    <div className="flex flex-row gap-8 justify-center">
                        <p>Like what you see? Have suggestions? Fork this repo!</p>
                        <iframe src="https://ghbtns.com/github-btn.html?user=anthonyshibitov&repo=netdis&type=fork&count=true&size=large" frameborder="0" scrolling="0" width="170" height="30" title="GitHub"></iframe>
                    </div>
                </div>
            </div>
        </div>
    )
}