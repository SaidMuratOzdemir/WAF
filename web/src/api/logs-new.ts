// web/src/api/logs-new.ts

import { apiFetch } from './client';

export interface LogEntry {
  id: string;
  ip: string;
  method: string;
  status: number;
  url: string;
  host: string;
  timestamp: string;
  request: string;
  response: string;
  site_name?: string;
  is_blocked?: boolean;
  block_reason?: string;
}

export interface LogsResponse {
  logs: LogEntry[];
  total: number;
  page: number;
  hasMore: boolean;
}

export interface LogDetails {
  request: {
    headers: Record<string, string>;
    body: string;
    method: string;
    path: string;
    query_string: string;
    client_ip: string;
    user_agent: string;
    content_type: string;
    content_length: number;
  };
  response?: {
    status_code: number;
    headers: Record<string, string>;
    body: string;
    content_type: string;
    content_length: number;
    processing_time_ms: number;
  };
}

// API functions
export async function getLogs(params: {
  page?: number;
  limit?: number;
  site_name?: string;
  client_ip?: string;
  method?: string;
  blocked_only?: boolean;
} = {}): Promise<LogsResponse> {
  const searchParams = new URLSearchParams();
  if (params.page) searchParams.append('page', params.page.toString());
  if (params.limit) searchParams.append('limit', params.limit.toString());
  if (params.site_name) searchParams.append('site_name', params.site_name);
  if (params.client_ip) searchParams.append('client_ip', params.client_ip);
  if (params.method) searchParams.append('method', params.method);
  if (params.blocked_only) searchParams.append('blocked_only', 'true');
  
  const query = searchParams.toString();
  return apiFetch<LogsResponse>(`/logs/requests${query ? `?${query}` : ''}`);
}

export async function getLogDetails(logId: string): Promise<LogDetails> {
  return apiFetch<LogDetails>(`/logs/requests/${logId}`);
} 