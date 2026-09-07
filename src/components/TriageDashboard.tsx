import React, { useState } from 'react';
import { analysisData, VulnerabilityFinding, FunctionNode, TriageVerdict, Confidence, VerificationStatus } from '../data/analysis-data';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import VerificationDialog from './VerificationDialog';

const initialFindings: (FunctionNode & {vulnerability: VulnerabilityFinding})[] = analysisData.nodes.filter(n => n.vulnerability) as any;

const TriageDashboard: React.FC = () => {
  const [findings, setFindings] = useState(initialFindings);
  const [verdictFilter, setVerdictFilter] = useState<TriageVerdict | 'all'>('all');
  const [confidenceFilter, setConfidenceFilter] = useState<Confidence | 'all'>('all');
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<(FunctionNode & {vulnerability: VulnerabilityFinding}) | null>(null);

  const handleOpenDialog = (finding: FunctionNode & {vulnerability: VulnerabilityFinding}) => {
    setSelectedFinding(finding);
    setIsDialogOpen(true);
  };

  const handleSaveStatus = (newStatus: VerificationStatus) => {
    if (selectedFinding) {
      const updatedFindings = findings.map(f => 
        f.id === selectedFinding.id 
          ? { ...f, vulnerability: { ...f.vulnerability, pass2_triage: { ...f.vulnerability.pass2_triage, status: newStatus } } } 
          : f
      );
      setFindings(updatedFindings);
    }
  };

  const filteredFindings = findings.filter(node => {
    const verdictMatch = verdictFilter === 'all' || node.vulnerability.pass2_triage.verdict === verdictFilter;
    const confidenceMatch = confidenceFilter === 'all' || node.vulnerability.pass1_hypothesis.confidence === confidenceFilter;
    return verdictMatch && confidenceMatch;
  });

  return (
    <div className="p-4 bg-gray-900 text-white h-full">
        <h2 className="text-2xl font-bold text-cyan-400 mb-4">Vulnerability Findings</h2>
        
        <div className="flex space-x-4 mb-4">
            {/* Filter UI */}
        </div>

        <Table>
            <TableHeader>
                <TableRow>
                    <TableHead>Function</TableHead>
                    <TableHead>CWE</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Triage Verdict</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>File</TableHead>
                    <TableHead>Actions</TableHead>
                </TableRow>
            </TableHeader>
            <TableBody>
                {filteredFindings.map(node => (
                    <TableRow key={node.id}>
                        <TableCell className="font-medium">{node.name}</TableCell>
                        <TableCell>{node.vulnerability.pass1_hypothesis.cwe_guess}</TableCell>
                        <TableCell>
                            <Badge variant={node.vulnerability.pass1_hypothesis.confidence === 'critical' ? 'destructive' : 'default'}>
                                {node.vulnerability.pass1_hypothesis.confidence}
                            </Badge>
                        </TableCell>
                        <TableCell>
                            <Badge variant={node.vulnerability.pass2_triage.verdict === 'likely_vulnerable' ? 'destructive' : 'secondary'}>
                                {node.vulnerability.pass2_triage.verdict}
                            </Badge>
                        </TableCell>
                        <TableCell>
                            <Badge variant={node.vulnerability.pass2_triage.status === 'confirmed_vulnerable' ? 'destructive' : 'outline'}>
                                {node.vulnerability.pass2_triage.status}
                            </Badge>
                        </TableCell>
                        <TableCell>{node.filePath}</TableCell>
                        <TableCell>
                            <Button variant="outline" size="sm" onClick={() => handleOpenDialog(node)}>Update</Button>
                        </TableCell>
                    </TableRow>
                ))}
            </TableBody>
        </Table>
        {selectedFinding && (
            <VerificationDialog 
                isOpen={isDialogOpen}
                onClose={() => setIsDialogOpen(false)}
                currentStatus={selectedFinding.vulnerability.pass2_triage.status}
                onSave={handleSaveStatus}
            />
        )}
    </div>
  );
};

export default TriageDashboard;
