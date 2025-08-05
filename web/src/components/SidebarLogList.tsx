// src/components/SidebarLogList.tsx

import { useInfiniteQuery } from '@tanstack/react-query';
import { getLogs, LogEntry } from '@/api/logs-new';
import { useRef, useEffect } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { getMethodColor, getStatusColor } from './HeaderInfo';
import { format } from 'date-fns';

interface SidebarLogListProps {
  selectedLogId: string | null;
  onLogSelect: (log: LogEntry) => void;
}
export function SidebarLogList({ selectedLogId, onLogSelect }: SidebarLogListProps) {
  const {
    data,
    isLoading,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery({
    queryKey: ['logs'],
    queryFn: ({ pageParam = 1 }) => getLogs({ page: pageParam, limit: 20 }),
    getNextPageParam: (last: any) => last.hasMore ? last.page + 1 : undefined,
    initialPageParam: 1,
    staleTime: 300_000,
  });


  const observerRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = observerRef.current;
    if (!el || !hasNextPage) return;
    const obs = new IntersectionObserver(entries => {
      if (entries[0].isIntersecting) fetchNextPage();
    });
    obs.observe(el);
    return () => obs.disconnect();
  }, [fetchNextPage, hasNextPage]);

  return (
    <ScrollArea className="h-full bg-background">
      <div className="p-4 space-y-2">
        {isLoading ? (
          Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-16 rounded-md" />
          ))
        ) : (
          data?.pages.map((page: any) =>
            page.logs.map((log: any) => {
              const isActive = log.id === selectedLogId;
              return (
                <Card
                  key={log.id}
                  onClick={() => onLogSelect(log)}
                  className={cn(
                    'cursor-pointer transition-all duration-200',
                    isActive
                      ? 'border-2 border-primary bg-primary/10 shadow-md'
                      : 'border border-transparent hover:shadow-md hover:bg-muted/50'
                  )}
                >
                  <CardContent className="p-3">
                    <div className="flex justify-between items-center mb-2">
                      <span className="font-mono text-sm text-foreground">{log.ip}</span>
                      <span className={`font-semibold text-sm ${getMethodColor(log.method)}`}>
                        {log.method}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className={`text-sm font-medium ${getStatusColor(log.status)}`}>
                        {log.status}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {format(new Date(log.timestamp), 'dd.MM.yyyy HH:mm')}
                      </span>
                    </div>
                  </CardContent>
                </Card>
              );
            })
          )
        )}
        <div ref={observerRef} className="h-4" />
        {isFetchingNextPage && <Skeleton className="h-16 rounded-md" />}
      </div>
    </ScrollArea>
  );
}
