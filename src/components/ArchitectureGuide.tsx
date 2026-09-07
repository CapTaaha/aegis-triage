import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { analysisData } from '../data/analysis-data';

const ArchitectureGuide: React.FC = () => {

  const exportJSON = () => {
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(
      JSON.stringify(analysisData, null, 2)
    )}`;
    const link = document.createElement("a");
    link.href = jsonString;
    link.download = "aegis-triage-report.json";
    link.click();
  };

  const exportMarkdown = () => {
    let markdown = `# AegisTriage Vulnerability Report\\n\\n`;
    analysisData.nodes.forEach(node => {
        if(node.vulnerability) {
            markdown += `## ${node.name}\\n\\n`;
            markdown += `**File:** ${node.filePath}:${node.startLine}-${node.endLine}\\n\\n`;
            markdown += `**CWE:** ${node.vulnerability.pass1_hypothesis.cwe_guess}\\n`;
            markdown += `**Confidence:** ${node.vulnerability.pass1_hypothesis.confidence}\\n`;
            markdown += `**Triage Verdict:** ${node.vulnerability.pass2_triage.verdict}\\n`;
            markdown += `**Verification Status:** ${node.vulnerability.pass2_triage.status}\\n\\n`;
            markdown += `### LLM Pass 1: Hypothesis\\n${node.vulnerability.pass1_hypothesis.reasoning}\\n\\n`;
            markdown += `### LLM Pass 2: Triage\\n${node.vulnerability.pass2_triage.explanation}\\n\\n`;
            markdown += `**Recommendation:**\\n\`\`\`\\n${node.vulnerability.pass2_triage.recommendation}\\n\`\`\`\\n\\n`;
            markdown += `---`;
        }
    });

    const markdownString = `data:text/markdown;charset=utf-8,${encodeURIComponent(markdown)}`;
    const link = document.createElement("a");
    link.href = markdownString;
    link.download = "aegis-triage-report.md";
    link.click();
  };

  return (
    <Card className="bg-gray-800 border-gray-700 text-gray-200">
      <CardHeader>
        <CardTitle className="text-cyan-400">Architecture & Exports</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div>
            <h3 className="text-xl font-semibold text-emerald-400 mb-2">Pipeline Architecture</h3>
            <p className="text-gray-400">
                This application demonstrates a multi-stage vulnerability discovery and triage pipeline. 
                The architecture is designed to be modular and extensible.
            </p>
            <ol className="list-decimal list-inside mt-2 text-gray-400 space-y-1">
                <li><span className="font-semibold">Static Analysis:</span> The pipeline begins by parsing the target application's source code into an Abstract Syntax Tree (AST) and constructing a call graph.</li>
                <li><span className="font-semibold">Heuristic Pre-filtering:</span> To save costs and reduce noise, a set of heuristics is used to identify potentially risky functions.</li>
                <li><span className="font-semibold">LLM Pass 1 (Hypothesis Generation):</span> Candidate functions are sent to an LLM to generate initial vulnerability hypotheses.</li>
                <li><span className="font-semibold">LLM Pass 2 (Triage & Classification):</span> The hypotheses from Pass 1 are reviewed by a second LLM pass with a stricter prompt to reduce false positives.</li>
                <li><span className="font-semibold">Manual Verification:</span> The final, triaged findings are presented in the dashboard for a human analyst to verify.</li>
            </ol>
        </div>
        <div>
            <h3 className="text-xl font-semibold text-emerald-400 mb-2">Export Findings</h3>
            <p className="text-gray-400 mb-4">Export the complete analysis data and vulnerability report in various formats.</p>
            <div className="flex space-x-4">
                <Button onClick={exportJSON} className="bg-emerald-500 hover:bg-emerald-600">Export as JSON</Button>
                <Button onClick={exportMarkdown} className="bg-emerald-500 hover:bg-emerald-600">Export as Markdown</Button>
            </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default ArchitectureGuide;
