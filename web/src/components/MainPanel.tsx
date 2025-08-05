// src/components/MainPanel.tsx

import { useQuery } from '@tanstack/react-query';
import { getLogDetails } from '@/api/logs';
import { HeaderInfo } from './HeaderInfo';
import { LogDetailPanel } from './LogDetailPanel';
import { LogEntry } from '@/api/logs';

interface MainPanelProps {
  selectedLog: LogEntry | null;
}

export function MainPanel({ selectedLog }: MainPanelProps) {
  const {
    data: logDetails,
    isLoading: isDetailsLoading
  } = useQuery({
    queryKey: ['logDetails', selectedLog?.id],
    queryFn: () => selectedLog ? getLogDetails(selectedLog.id) : Promise.resolve(null),
    enabled: !!selectedLog,
    staleTime: 300_000,
  });

  if (!selectedLog) {
    return (
      <div className="flex-1 p-6 flex items-center justify-center">
        <div className="text-center text-muted-foreground">
          <h2 className="text-2xl font-semibold mb-2">WAF Log Viewer</h2>
          <p>Select a log entry from the sidebar to view details</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 p-6 overflow-y-auto space-y-6">
      <HeaderInfo selectedLog={selectedLog} />
      <LogDetailPanel logDetails={logDetails || null} isLoading={isDetailsLoading} />
    </div>
  );
}
