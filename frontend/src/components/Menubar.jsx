import { useContext, useState } from "react";
import MenuBarItem from "./MenuBarItem";
import { info } from "autoprefixer";
import { MenuContext } from "../context/MenuContext";
import Upload from "./Upload"
import { useNavigate } from "react-router-dom";

export default function MenuBar() {
    const navigate = useNavigate();
    const [showModal, setShowModal] = useState(false);
    const [menuContext, setMenuContext] = useContext(MenuContext);

    function toggleModal(){
        const currentValue = showModal;
        setShowModal(!currentValue);
    }

    const fileSubMenu = {
        "Open": function(){
            toggleModal();
        },
        "Quit": function(){
            navigate('/');
        },
    }

    const optionsSubMenu = {
        "Auto-analyze": "a",
        "Highlight": "b",
    }

    const windowsSubmenu = {
        "Disassembly": function(){
            if(menuContext.disasmView){
                setMenuContext({...menuContext, disasmView: false})
            } else {
                setMenuContext({...menuContext, disasmView: true})
            }
        },
        "Decompilation": function(){
            if(menuContext.decompView){
                setMenuContext({...menuContext, decompView: false})
            } else {
                setMenuContext({...menuContext, decompView: true})
            }
        },
        "Control Flow Graph": function(){
            if(menuContext.cfgView){
                setMenuContext({...menuContext, cfgView: false})
            } else {
                setMenuContext({...menuContext, cfgView: true})
            }
        },
        "Function List": function(){
            if(menuContext.functionView){
                setMenuContext({...menuContext, functionView: false})
            } else {
                setMenuContext({...menuContext, functionView: true})
            }
        },
    }

    const helpSubmenu = {
        "About": function(){
            const win = window.open('/info', '_blank');
            win.focus();
        },
        "Github Repo": function(){
            const win = window.open('https://github.com/anthonyshibitov/netdis', '_blank');
            win.focus();
        },
    }
    
    return (
        <div className="border-b border-ndblue flex font-mono items-center text-xs font-bold bg-ccc h-5">
            <div className="px-4 pt-1"><span className="text-ndblue">net</span><span className="text-ndgrey">dis</span></div>
            <MenuBarItem name="File"
                subMenu={fileSubMenu}
            />
            <MenuBarItem name="Options" 
                subMenu={optionsSubMenu}
            />
            <MenuBarItem name="Windows"
                subMenu={windowsSubmenu}
            />
            <MenuBarItem name="Help" 
                subMenu={helpSubmenu}
            />
            {showModal && (
                <div className="z-50 fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center">
                    <div className="bg-white p-4 rounded flex flex-col">
                        <Upload callback={toggleModal}/>
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