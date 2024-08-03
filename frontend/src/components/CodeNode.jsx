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
            console.log("UPDATED CODENODE REF")
            console.log(`for data id ${data.label}`)
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
            <Handle type="target" position="top" style={{ background: '#555' }} />
            <Handle type="source" position="bottom" style={{ background: '#555' }} />
        </div>
    );
};

export default CodeNode;