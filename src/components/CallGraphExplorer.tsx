import React, { useCallback } from 'react';
import ReactFlow, {
  addEdge,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  NodeMouseHandler,
} from 'reactflow';

import 'reactflow/dist/style.css';
import { analysisData, FunctionNode, CallEdge } from '../data/analysis-data';

const initialNodes: Node<FunctionNode>[] = analysisData.nodes.map((node, i) => ({
    id: node.id,
    type: 'default',
    data: node,
    position: { x: i * 250, y: Math.random() * 200 },
}));

const initialEdges: Edge<CallEdge>[] = analysisData.edges.map(edge => ({
    id: `${edge.source}-${edge.target}`,
    source: edge.source,
    target: edge.target,
    label: 'calls',
    type: 'smoothstep',
    animated: true,
}));

interface CallGraphExplorerProps {
  onNodeClick: (node: FunctionNode) => void;
}

const CallGraphExplorer: React.FC<CallGraphExplorerProps> = ({ onNodeClick }) => {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  const handleNodeClick: NodeMouseHandler = useCallback((event, node) => {
    onNodeClick(node.data as FunctionNode);
  }, [onNodeClick]);

  const onConnect = useCallback(
    (params: any) => setEdges((eds) => addEdge(params, eds)),
    [setEdges],
  );

  return (
    <div style={{ height: '100vh', width: '100%', background: '#1a1a1a' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onNodeClick={handleNodeClick}
        fitView
        attributionPosition="top-right"
      >
        <Controls />
        <MiniMap />
        <Background color="#333" gap={16} />
      </ReactFlow>
    </div>
  );
};

export default CallGraphExplorer;
