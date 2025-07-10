// src/api/ips.ts

const API_URL = '/api';

export interface IPInfo {
  ip: string;
  banned_at?: string;
  added_at?: string;
}

const getAuthHeaders = () => ({
  'Authorization': `Bearer ${localStorage.getItem('token')}`
});

export const getBannedIPs = async (): Promise<IPInfo[]> => {
  const response = await fetch(`${API_URL}/ips/banned`, {
    credentials: 'include',
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error('Failed to fetch banned IPs');
  }
  return response.json();
};

export const getCleanIPs = async (): Promise<IPInfo[]> => {
  const response = await fetch(`${API_URL}/ips/clean`, {
    credentials: 'include',
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error('Failed to fetch clean IPs');
  }
  return response.json();
};

export const banIP = async (ip: string): Promise<void> => {
  const response = await fetch(`${API_URL}/ips/ban/${ip}`, {
    method: 'POST',
    credentials: 'include',
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error('Failed to ban IP');
  }
};

export const unbanIP = async (ip: string): Promise<void> => {
  const response = await fetch(`${API_URL}/ips/unban/${ip}`, {
    method: 'POST',
    credentials: 'include',
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error('Failed to unban IP');
  }
};

export const whitelistIP = async (ip: string): Promise<void> => {
  const response = await fetch(`${API_URL}/ips/whitelist/${ip}`, {
    method: 'POST',
    credentials: 'include',
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error('Failed to whitelist IP');
  }
};

export const unwhitelistIP = async (ip: string): Promise<void> => {
  const response = await fetch(`${API_URL}/ips/unwhitelist/${ip}`, {
    method: 'POST',
    credentials: 'include',
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    throw new Error('Failed to remove IP from whitelist');
  }
};
