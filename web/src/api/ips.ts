import { apiFetch } from './client';

export interface IPInfo {
  ip: string;
  banned_at?: string;
  added_at?: string;
}

export const getBannedIPs = async (): Promise<IPInfo[]> => apiFetch('/ips/banned');
export const getCleanIPs = async (): Promise<IPInfo[]> => apiFetch('/ips/clean');
export const banIP = async (ip: string): Promise<void> => apiFetch(`/ips/ban/${ip}`, { method: 'POST' });
export const unbanIP = async (ip: string): Promise<void> => apiFetch(`/ips/unban/${ip}`, { method: 'POST' });
