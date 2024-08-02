import React from 'react';
import { Handle, Position } from '@xyflow/react';
import './CodeNode.css';

const CodeNode = ({ data }) => {
    console.log("Data passed to code node");
    console.log(data);
    return (
        <div className="code-node">
        {/* <div>{data.label}</div> */}
        <div>{data.text.map(line => {
            return (
                <div className="codenode-line">
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