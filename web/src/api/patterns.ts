import { Pattern, PatternCreate, PatternUpdate } from '../types/Pattern';

const API_URL = '/api/patterns';

function authHeaders(extra: any = {}) {
  const token = localStorage.getItem('token');
  return {
    'Authorization': token ? `Bearer ${token}` : '',
    ...extra
  };
}

export async function getPatterns(type?: string): Promise<Pattern[]> {
  const url = type ? `${API_URL}?type=${type}` : API_URL;
  const res = await fetch(url, { headers: authHeaders() });
  if (!res.ok) throw new Error('Pattern listesi alınamadı');
  return res.json();
}

export async function addPattern(pattern: PatternCreate): Promise<Pattern> {
  const res = await fetch(API_URL, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ patterns: [pattern] })
  });
  if (!res.ok) throw new Error('Pattern eklenemedi');
  return (await res.json())[0];
}

export async function addPatternsFromTxt(file: File, type: string): Promise<Pattern[]> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('type', type);
  const res = await fetch(API_URL, {
    method: 'POST',
    headers: authHeaders(),
    body: formData
  });
  if (!res.ok) throw new Error('TXT ile pattern eklenemedi');
  return await res.json();
}

export async function updatePattern(id: number, update: PatternUpdate): Promise<Pattern> {
  const res = await fetch(`${API_URL}/${id}`, {
    method: 'PUT',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(update)
  });
  if (!res.ok) throw new Error('Pattern güncellenemedi');
  return await res.json();
}

export async function deletePattern(id: number): Promise<void> {
  const res = await fetch(`${API_URL}/${id}`, {
    method: 'DELETE', headers: authHeaders() });
  if (!res.ok) throw new Error('Pattern silinemedi');
} 