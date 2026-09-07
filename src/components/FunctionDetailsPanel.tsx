import React from 'react';
import { FunctionNode } from '../data/analysis-data';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';

interface FunctionDetailsPanelProps {
  node: FunctionNode | null;
}

const FunctionDetailsPanel: React.FC<FunctionDetailsPanelProps> = ({ node }) => {
  if (!node) {
    return (
      <Card className="h-full bg-gray-800 border-gray-700">
        <CardHeader>
          <CardTitle className="text-emerald-400">No Function Selected</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-gray-400">Click on a node in the graph to see its details.</p>
        </CardContent>
      </Card>
    );
  }

  const { name, filePath, startLine, endLine, sourceCode, vulnerability } = node;

  return (
    <Card className="h-full bg-gray-800 border-gray-700 text-gray-200">
      <CardHeader>
        <CardTitle className="text-emerald-400">{name}</CardTitle>
        <p className="text-sm text-gray-500">{filePath}:{startLine}-{endLine}</p>
      </CardHeader>
      <CardContent>
        <div className="mb-4">
            <h3 className="text-lg font-semibold text-cyan-400 mb-2">Source Code</h3>
            <pre className="bg-gray-900 p-4 rounded-md overflow-auto text-sm"><code>{sourceCode}</code></pre>
        </div>
        {vulnerability && (
            <div>
                <h3 className="text-lg font-semibold text-cyan-400 mb-2">Vulnerability Analysis</h3>
                <div className="space-y-4">
                    <div>
                        <h4 className="font-bold text-amber-400">LLM Pass 1: Hypothesis</h4>
                        <p><Badge variant={vulnerability.pass1_hypothesis.confidence === 'critical' ? 'destructive' : 'default'}>{vulnerability.pass1_hypothesis.confidence}</Badge> {vulnerability.pass1_hypothesis.cwe_guess}</p>
                        <p className="text-sm mt-1">{vulnerability.pass1_hypothesis.reasoning}</p>
                    </div>
                    <div>
                        <h4 className="font-bold text-teal-400">LLM Pass 2: Triage</h4>
                        <p><Badge variant={vulnerability.pass2_triage.verdict === 'likely_vulnerable' ? 'destructive' : 'secondary'}>{vulnerability.pass2_triage.verdict}</Badge></p>
                        <p className="text-sm mt-1">{vulnerability.pass2_triage.explanation}</p>
                        <p className="text-sm mt-2 font-mono bg-gray-900 p-2 rounded">Recommendation: {vulnerability.pass2_triage.recommendation}</p>
                    </div>
                </div>
            </div>
        )}
      </CardContent>
    </Card>
  );
};

export default FunctionDetailsPanel;
