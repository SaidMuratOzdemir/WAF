// src/components/HeaderInfo.tsx

import { Card, CardContent } from '@/components/ui/card';
import { LogEntry } from '@/api/logs';

export function getStatusColor(status: number) {
  if (status >= 200 && status < 300) return 'text-green-600';
  if (status >= 300 && status < 400) return 'text-blue-600';
  if (status >= 400 && status < 500) return 'text-yellow-600';
  if (status >= 500) return 'text-red-600';
  return 'text-gray-600';
}

export function getMethodColor(method: string) {
  switch (method.toUpperCase()) {
    case 'GET':    return 'text-blue-600';
    case 'POST':   return 'text-green-600';
    case 'PUT':    return 'text-yellow-600';
    case 'DELETE': return 'text-red-600';
    case 'PATCH':  return 'text-purple-600';
    default:       return 'text-gray-600';
  }
}

interface HeaderInfoProps {
  selectedLog: LogEntry | null;
}

export function HeaderInfo({ selectedLog }: HeaderInfoProps) {
  const fmtTime = (ts: string) =>
    new Date(ts).toLocaleString('tr-TR', { hour12: false });

  if (!selectedLog) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 mb-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <Card key={i} className="animate-pulse">
            <CardContent className="p-4">
              <div className="h-4 bg-muted rounded w-3/4 mb-2"></div>
              <div className="h-6 bg-muted rounded w-full"></div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  const items = [
    { label: 'Request URL',   value: selectedLog.url },
    { label: 'Host',          value: selectedLog.host },
    { label: 'HTTP Method',   value: selectedLog.method,   color: getMethodColor(selectedLog.method) },
    { label: 'Status Code',   value: selectedLog.status,   color: getStatusColor(selectedLog.status) },
    { label: 'Time',          value: fmtTime(selectedLog.timestamp) },
    { label: 'Source IP',     value: selectedLog.ip }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
      {items.map((it, i) => (
        <Card key={i} className="hover:shadow-md transition-shadow">
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground mb-1">{it.label}</p>
            <p className={`text-base font-medium ${it.color ?? 'text-foreground'} break-all`}>
              {it.value}
            </p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
