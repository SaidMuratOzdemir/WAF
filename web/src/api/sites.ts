import type { Site, SiteCreate } from '../types/Site';

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

export const addSite = async (site: SiteCreate): Promise<Site> => {
    console.log('addSite called with:', site);
    console.log('addSite JSON stringify:', JSON.stringify(site));
    
    const response = await fetch(`${API_URL}/sites`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(site)
    });
    
    if (!response.ok) {
        const errorText = await response.text();
        console.error('API Error:', {
            status: response.status,
            statusText: response.statusText,
            body: errorText
        });
        
        // Parse error message for better user experience
        if (response.status === 409) {
            const errorData = JSON.parse(errorText);
            throw new Error(errorData.detail || 'Site already exists with this port and host combination');
        } else if (response.status === 422) {
            const errorData = JSON.parse(errorText);
            const validationErrors = errorData.detail;
            if (Array.isArray(validationErrors)) {
                const missingFields = validationErrors
                    .filter(err => err.type === 'missing')
                    .map(err => err.loc[err.loc.length - 1]);
                
                if (missingFields.length > 0) {
                    throw new Error(`Required fields are missing: ${missingFields.join(', ')}`);
                }
                
                const errorMessages = validationErrors.map((err: any) => 
                    `${err.loc.join('.')}: ${err.msg}`
                ).join(', ');
                throw new Error(`Validation error: ${errorMessages}`);
            }
        }
        
        throw new Error(`Failed to add site: ${response.status} ${response.statusText} - ${errorText}`);
    }
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
