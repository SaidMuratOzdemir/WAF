// Merkezi API client
const BASE_URL = '/api/v1';

export async function apiFetch<T = any>(path: string, options: RequestInit = {}) {
  const token = localStorage.getItem('token');
  const isFormData = options.body instanceof FormData;
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (!isFormData) headers['Content-Type'] = 'application/json';
  if (options.headers) {
    Object.entries(options.headers).forEach(([k, v]) => {
      if (typeof v === 'string') headers[k] = v;
    });
  }
  const response = await fetch(`${BASE_URL}${path}`, { ...options, headers });
  if (response.status === 401 || response.status === 403) {
    localStorage.removeItem('token');
    window.location.href = '/login';
    throw new Error('Session expired, please log in again.');
  }
  if (!response.ok) {
    let error: any = {};
    try { error = await response.json(); } catch {}
    throw new Error(error.detail || response.statusText);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
} 