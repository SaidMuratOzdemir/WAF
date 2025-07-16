import { Pattern, PatternCreate, PatternUpdate, PatternType } from '../types/Pattern';
import { apiFetch } from './client';

export interface PatternPage {
  items: Pattern[];
  total: number;
}

export interface PatternUploadResult {
  success: number;
  failed: number;
  errors: string[];
}

export async function getPatterns(
  page: number = 1,
  pageSize: number = 20,
  type?: PatternType,
  search?: string
): Promise<PatternPage> {
  const params = new URLSearchParams();
  params.append('limit', String(pageSize));
  params.append('offset', String((page - 1) * pageSize));
  if (type) params.append('pattern_type', type); // DÜZELTİLDİ
  if (search) params.append('search', search);
  return apiFetch<PatternPage>(`/patterns?${params.toString()}`);
}

export async function addPattern(pattern: PatternCreate): Promise<Pattern> {
  return apiFetch('/patterns/single', {
    method: 'POST',
    body: JSON.stringify(pattern)
  });
}

export async function addPatternsFromTxt(file: File, type: PatternType): Promise<PatternUploadResult> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('type', type);
  return apiFetch('/patterns', { method: 'POST', body: formData });
}

export async function updatePattern(id: number, update: PatternUpdate): Promise<Pattern> {
  return apiFetch(`/patterns/${id}`, {
    method: 'PUT',
    body: JSON.stringify(update)
  });
}

export async function deletePattern(id: number): Promise<void> {
  return apiFetch(`/patterns/${id}`, { method: 'DELETE' });
} 