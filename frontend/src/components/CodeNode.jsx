import React, { useRef, useEffect, useState, useContext } from 'react';
import { Handle, Position } from '@xyflow/react';
import './CodeNode.css';
import { NodeSizeContext } from '../context/NodeSizeContext.jsx';

const CodeNode = ({ data }) => {
    const nodeRef = useRef(null);
    const { updateNodeSize } = useContext(NodeSizeContext);

    useEffect(() => {
        if(nodeRef.current){
            const { offsetWidth, offsetHeight } = nodeRef.current;
            updateNodeSize(data.label, { width: offsetWidth, height: offsetHeight })
        }
    }, [data])

    return (
        <div ref={nodeRef} className="code-node">
            <div>{data.label}</div>
            <div>{data.text.map((line, index) => {
                return (
                    <div key={index} className="codenode-line">
                        <span className="codenode-addr">{line.addr}: </span>
                        <span className="codenode-op">{line.op} </span>
                        <div className="codenode-data">{line.data}</div>
                    </div>
                )})}
            </div>
            <Handle type="target" position="top" />
            <Handle type="source" position="bottom" />
        </div>
    );
};

export default CodeNode;