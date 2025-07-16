// src/api/sites.ts

import type {Site, SiteCreate} from '../types/Site';
import { apiFetch } from './client';

export const fetchSites = async (): Promise<Site[]> => apiFetch('/sites');
export const addSite = async (site: SiteCreate): Promise<Site> => apiFetch('/sites', { method: 'POST', body: JSON.stringify(site) });
export const updateSite = async (id: number, site: Partial<Omit<Site, 'id'>>): Promise<Site> => apiFetch(`/sites/${id}`, { method: 'PUT', body: JSON.stringify(site) });
export const deleteSite = async (id: number): Promise<void> => apiFetch(`/sites/${id}`, { method: 'DELETE' });
