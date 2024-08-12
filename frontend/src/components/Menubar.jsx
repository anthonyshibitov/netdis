import { useContext, useState } from "react";
import MenuBarItem from "./MenuBarItem";
import { info } from "autoprefixer";

export default function MenuBar() {

    const fileSubMenu = {
        "Open": "a",
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

    function openMenu(menu){
        for(const m in menu){
            console.log(m);
        }
    }
    
    return (
        <div className="border-b border-ndblue flex font-mono items-center text-xs font-bold bg-ccc h-5">
            <MenuBarItem name="File"
                subMenu={fileSubMenu}
            />
            <MenuBarItem name="Options" 
                subMenu={optionsSubMenu}
            />
            <MenuBarItem name="Info" 
                subMenu={infoSubmenu}
            />
        </div>
    )
}