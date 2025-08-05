// src/WAFLogViewer.tsx

import { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { SidebarLogList } from '@/components/SidebarLogList';
import { MainPanel } from '@/components/MainPanel';
import { LogEntry } from '@/api/logs-new';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 300_000,
      retry: 1,
    },
  },
});

export default function WAFLogViewer() {
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  return (
    <QueryClientProvider client={queryClient}>
      <div className="flex h-screen bg-background text-foreground">
        {/* Sidebar */}
        <div className="w-96 border-r bg-card">
          <SidebarLogList
            selectedLogId={selectedLog?.id || null}
            onLogSelect={setSelectedLog}
          />
        </div>
        {/* Main */}
        <div className="flex-1 overflow-hidden">
          <MainPanel selectedLog={selectedLog} />
        </div>
      </div>
    </QueryClientProvider>
  );
}
