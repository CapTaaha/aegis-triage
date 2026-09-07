import React from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from './ui/dialog';
import { Button } from './ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { VerificationStatus } from '../data/analysis-data';

interface VerificationDialogProps {
  isOpen: boolean;
  onClose: () => void;
  currentStatus: VerificationStatus;
  onSave: (newStatus: VerificationStatus) => void;
}

const VerificationDialog: React.FC<VerificationDialogProps> = ({ isOpen, onClose, currentStatus, onSave }) => {
  const [status, setStatus] = React.useState(currentStatus);

  const handleSave = () => {
    onSave(status);
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="bg-gray-800 border-gray-700 text-white">
        <DialogHeader>
          <DialogTitle className="text-cyan-400">Update Verification Status</DialogTitle>
        </DialogHeader>
        <div className="py-4">
          <Select onValueChange={(value: VerificationStatus) => setStatus(value)} defaultValue={status}>
            <SelectTrigger className="bg-gray-700 border-gray-600">
              <SelectValue placeholder="Select a status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="pending">Pending</SelectItem>
              <SelectItem value="in_progress">In Progress</SelectItem>
              <SelectItem value="confirmed_vulnerable">Confirmed Vulnerable</SelectItem>
              <SelectItem value="confirmed_safe">Confirmed Safe</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button className="bg-emerald-500 hover:bg-emerald-600" onClick={handleSave}>Save</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default VerificationDialog;
