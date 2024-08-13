import { useContext, useState } from "react";
import MenuBarItem from "./MenuBarItem";
import { info } from "autoprefixer";
import { MenuContext } from "../context/MenuContext";

export default function MenuBar() {
    const [menuContext, setMenuContext] = useContext(MenuContext);

    const fileSubMenu = {
        "Open": function(){
            console.log("OPEN FUNCTION")
        },
        "Close": "b",
        "Quit": "c",
    }

    const optionsSubMenu = {
        "Auto-analyze": "a",
        "Highlight": "b",
    }

    const infoSubmenu = {
        "About": "a",
        "Github Repo": "b",
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

    function openMenu(menu){
        for(const m in menu){
            console.log(m);
        }
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
            <MenuBarItem name="Info" 
                subMenu={infoSubmenu}
            />
            <MenuBarItem name="Windows"
                subMenu={windowsSubmenu}
            />
        </div>
    )
}