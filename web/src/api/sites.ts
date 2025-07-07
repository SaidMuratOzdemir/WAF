import type { Site } from '../types/Site';

const API_URL = 'http://localhost:8001';

export const fetchSites = async (): Promise<Site[]> => {
    const response = await fetch(`${API_URL}/sites`, {
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
    });
    if (!response.ok) throw new Error('Failed to fetch sites');
    return response.json();
};

export const addSite = async (site: Site): Promise<Site> => {
    const response = await fetch(`${API_URL}/sites`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(site)
    });
    if (!response.ok) throw new Error('Failed to add site');
    return response.json();
};

export const deleteSite = async (port: number): Promise<void> => {
    const response = await fetch(`${API_URL}/sites/${port}`, {
        method: 'DELETE',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
    });
    if (!response.ok) throw new Error('Failed to delete site');
};
