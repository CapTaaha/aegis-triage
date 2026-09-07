import { useState } from 'react';
import CallGraphExplorer from '../components/CallGraphExplorer';
import FunctionDetailsPanel from '../components/FunctionDetailsPanel';
import LLMConfigurator from '../components/LLMConfigurator';
import TriageDashboard from '../components/TriageDashboard';
import ArchitectureGuide from '../components/ArchitectureGuide';
import { FunctionNode } from '../data/analysis-data';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';

export default function Index() {
  const [selectedNode, setSelectedNode] = useState<FunctionNode | null>(null);

  return (
    <main className="flex flex-col h-screen bg-gray-900 text-white">
      <header className="text-center py-4 border-b border-gray-700">
        <h1 className="text-3xl font-bold text-emerald-400">AegisTriage Dashboard</h1>
        <p className="text-sm text-gray-400">Automated Vulnerability Discovery & Triage Pipeline</p>
      </header>
      <Tabs defaultValue="call_graph" className="flex-1 flex flex-col">
        <TabsList className="bg-gray-800 border-b border-gray-700 justify-start rounded-none">
          <TabsTrigger value="call_graph">Call Graph Explorer</TabsTrigger>
          <TabsTrigger value="triage_dashboard">Triage Dashboard</TabsTrigger>
          <TabsTrigger value="architecture">Architecture & Exports</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>
        <TabsContent value="call_graph" className="flex-1 overflow-hidden">
            <div className="flex h-full">
                <div className="w-2/3 border-r border-gray-700">
                    <CallGraphExplorer onNodeClick={(node) => setSelectedNode(node)} />
                </div>
                <div className="w-1/3 overflow-y-auto p-4">
                    <FunctionDetailsPanel node={selectedNode} />
                </div>
            </div>
        </TabsContent>
        <TabsContent value="triage_dashboard" className="flex-1 overflow-hidden">
            <TriageDashboard />
        </TabsContent>
        <TabsContent value="architecture" className="p-8">
            <ArchitectureGuide />
        </TabsContent>
        <TabsContent value="settings" className="p-8">
          <LLMConfigurator />
        </TabsContent>
      </Tabs>
    </main>
  );
}
