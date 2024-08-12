import { useEffect, useRef, useState } from "react";

export default function MenuBarItem(props) {
    const name = props.name;
    const subMenu = props.subMenu;
    const menuRef = useRef();
    const [isOpen, setIsOpen] = useState(false);

    function clickHandler(){
        setIsOpen(true);
    }

    useEffect(() => {
        const handleClickOutside = (event) => {
            if (menuRef.current && !menuRef.current.contains(event.target)) {
              setIsOpen(false);
            }
          };
      
          // Bind the event listener
          document.addEventListener('mousedown', handleClickOutside);
      
          // Unbind the event listener on cleanup
          return () => {
            document.removeEventListener('mousedown', handleClickOutside);
          };
    }, [])

    return (
        <div ref={menuRef} className="z-10 relative px-4 pt-1 hover:bg-white cursor-pointer" onClick={clickHandler}>
            <div>{name}</div>
            {isOpen && (
                <div className="border border-ndblue border-t-0 flex flex-col absolute bg-ccc left-0">
                    {Object.entries(subMenu).map(([name, value]) => {
                        return (
                            <div className="whitespace-pre cursor-pointer px-4 flex hover:bg-white w-full" key={name}>{name}</div>
                        )
                    })}
                </div>
            )}
        </div>
    )
}