// src/components/LogDetailPanel.tsx

import { useState } from 'react';
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import { LogDetails } from '@/api/logs-new';

interface LogDetailPanelProps {
  logDetails: LogDetails | null;
  isLoading: boolean;
}

export function LogDetailPanel({ logDetails, isLoading }: LogDetailPanelProps) {
  const [tab, setTab] = useState<'request' | 'response'>('request');

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Log Details</CardTitle>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-6 w-32 mb-4" />
          <Skeleton className="h-64" />
        </CardContent>
      </Card>
    );
  }

  if (!logDetails) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Log Details</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center text-muted-foreground py-8">
            Select a log entry to view details
          </div>
        </CardContent>
      </Card>
    );
  }

  const fmtHeaders = (hdr: Record<string,string>) =>
    Object.entries(hdr).map(([k,v])=>`${k}: ${v}`).join('\n');

  const req = logDetails.request;
  const resp = logDetails.response;

  return (
    <Card className="shadow-sm hover:shadow-md transition-shadow">
      <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between pb-4">
        <CardTitle className="text-lg">Log Details</CardTitle>
          <ToggleGroup
            type="single"
            value={tab}
            onValueChange={v => v && setTab(v as any)}
            className="space-x-2"
          >
            <ToggleGroupItem
              value="request"
              className="
                px-3 py-1 rounded-md 
                data-[state=on]:bg-primary 
                data-[state=on]:text-primary-foreground
                data-[state=off]:bg-muted/20 
                data-[state=off]:text-muted-foreground
                transition-colors
                hover:bg-muted/40
              "
            >
              📨 Request
            </ToggleGroupItem>
            <ToggleGroupItem
              value="response"
              className="
                px-3 py-1 rounded-md 
                data-[state=on]:bg-primary 
                data-[state=on]:text-primary-foreground
                data-[state=off]:bg-muted/20 
                data-[state=off]:text-muted-foreground
                transition-colors
                hover:bg-muted/40
              "
            >
              📥 Response
            </ToggleGroupItem>
          </ToggleGroup>
      </CardHeader>

      <CardContent className="space-y-4">
        {tab === 'request' ? (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
              <div>
                <p className="text-sm text-muted-foreground mb-1">Method</p>
                <p className="text-base font-medium">{req.method}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-1">Path</p>
                <p className="text-base font-medium break-all">{req.path}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-1">IP</p>
                <p className="text-base font-medium">{req.client_ip}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-1">Content Length</p>
                <p className="text-base font-medium">{req.content_length}</p>
              </div>
              <div className="sm:col-span-2">
                <p className="text-sm text-muted-foreground mb-1">User Agent</p>
                <p className="text-base font-medium break-all">{req.user_agent}</p>
              </div>
            </div>
            <ScrollArea className="h-64 border rounded-md bg-muted/30">
              <pre className="whitespace-pre-wrap text-xs font-mono p-4">
                {`${req.method} ${req.path}${req.query_string ? '?' + req.query_string : ''}
${fmtHeaders(req.headers)}

${req.body || ''}`}
              </pre>
            </ScrollArea>
          </>
        ) : (
          <>
            {resp ? (
              <>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Status</p>
                    <p className="text-base font-medium">{resp.status_code}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Content Length</p>
                    <p className="text-base font-medium">{resp.content_length}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Processing Time</p>
                    <p className="text-base font-medium">{resp.processing_time_ms}ms</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Content Type</p>
                    <p className="text-base font-medium">{resp.content_type}</p>
                  </div>
                </div>
                <ScrollArea className="h-64 border rounded-md bg-muted/30">
                  <pre className="whitespace-pre-wrap text-xs font-mono p-4">
                    {`HTTP/1.1 ${resp.status_code}
${fmtHeaders(resp.headers)}

${resp.body || ''}`}
                  </pre>
                </ScrollArea>
              </>
            ) : (
              <div className="text-center text-muted-foreground py-8">
                No response data available
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
