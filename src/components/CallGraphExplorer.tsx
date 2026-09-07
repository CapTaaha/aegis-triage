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
import { useEffect } from 'react';
import { CallGraph, FunctionNode } from '../data/analysis-data';

type FunctionGraphData = FunctionNode & { label: string };

interface CallGraphExplorerProps {
  graph: CallGraph;
  onNodeClick: (node: FunctionNode) => void;
}

const CallGraphExplorer: React.FC<CallGraphExplorerProps> = ({ graph, onNodeClick }) => {
  const [nodes, setNodes, onNodesChange] = useNodesState<FunctionGraphData>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    const visible = [...graph.nodes]
      .sort((left, right) => Number(Boolean(right.vulnerability)) - Number(Boolean(left.vulnerability)))
      .slice(0, 180);
    const visibleIds = new Set(visible.map((node) => node.id));
    setNodes(visible.map((node, index) => ({
      id: node.id,
      data: { ...node, label: node.name },
      position: { x: (index % 4) * 260, y: Math.floor(index / 4) * 150 },
      style: {
        border: node.vulnerability ? '1px solid #fb7185' : '1px solid #34d399',
        borderRadius: 16,
        background: '#0f172a',
        color: '#e2e8f0',
        padding: 10,
      },
    })));
    setEdges(graph.edges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target)).map((edge) => ({
      id: `${edge.source}-${edge.target}`,
      source: edge.source,
      target: edge.target,
      label: 'calls',
      type: 'smoothstep',
      animated: true,
      style: { stroke: '#22d3ee' },
    })));
  }, [graph, setEdges, setNodes]);

  const handleNodeClick: NodeMouseHandler = useCallback((_event, node) => {
    onNodeClick(node.data as FunctionNode);
  }, [onNodeClick]);

  const onConnect = useCallback(
    (params: Parameters<typeof addEdge>[0]) => setEdges((current) => addEdge(params, current)),
    [setEdges],
  );

  return (
    <div className="h-full min-h-[520px] w-full bg-slate-950">
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
        <Controls className="overflow-hidden rounded-xl border border-slate-700 bg-slate-900 fill-slate-100" />
        <MiniMap className="rounded-xl border border-slate-700 bg-slate-900" nodeColor={(node) => node.data.vulnerability ? '#fb7185' : '#34d399'} />
        <Background color="#334155" gap={20} />
      </ReactFlow>
    </div>
  );
};

export default CallGraphExplorer;
