import React, { createContext, useState } from 'react';

export const NodeSizeContext = createContext();

export const NodeSizeProvider = ({ children }) => {
    const [nodeSizes, setNodeSizes] = useState({});

    const updateNodeSize = (nodeId, size) => {
        setNodeSizes(prevSizes => ({ ...prevSizes, [nodeId]: size }));
    };

    return (
        <NodeSizeContext.Provider value={{ nodeSizes, updateNodeSize }}>
            {children}
        </NodeSizeContext.Provider>
    );
};
