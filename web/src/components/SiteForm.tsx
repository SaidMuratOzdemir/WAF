import { useState } from 'react';
import {
    Box,
    TextField,
    Button,
    FormControlLabel,
    Switch,
    Paper,
    Typography,
    Alert,
    Stack
} from '@mui/material';
import type { Site } from '../types/Site';
import { addSite } from '../api/sites';

interface SiteFormProps {
    onSiteAdded: () => void;
}

export function SiteForm({ onSiteAdded }: SiteFormProps) {
    const [formData, setFormData] = useState<Site>({
        id: 0, // Will be set by backend
        port: 8081,
        host: '',
        name: '',
        frontend_url: '',
        backend_url: '',
        xss_enabled: true,
        sql_enabled: true,
        vt_enabled: false
    });
    const [error, setError] = useState<string>('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            // Validate required fields
            if (!formData.name.trim()) {
                throw new Error('Site name is required');
            }
            if (!formData.host.trim()) {
                throw new Error('Host field is required');
            }
            if (!formData.frontend_url.trim()) {
                throw new Error('Frontend URL is required');
            }
            if (!formData.backend_url.trim()) {
                throw new Error('Backend URL is required');
            }
            
            // Validate URLs
            try {
                new URL(formData.frontend_url);
                new URL(formData.backend_url);
            } catch {
                throw new Error('Please enter valid URLs');
            }

            // Exclude id field for API call since it's auto-generated
            const { id, ...siteData } = formData;
            const site = await addSite(siteData);
            onSiteAdded();
            
            // Reset form
            setFormData({
                id: 0,
                port: 8081,
                host: '',
                name: '',
                frontend_url: '',
                backend_url: '',
                xss_enabled: true,
                sql_enabled: true,
                vt_enabled: false
            });
            setError('');
        } catch (e) {
            console.error('Form submission error:', e);
            setError(e instanceof Error ? e.message : 'Failed to add site');
        }
    };

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: name === 'port' ? parseInt(value) || 0 : value
        }));
    };

    const handleSwitchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, checked } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: checked
        }));
    };

    return (
        <Paper elevation={2} sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
                Add New Protected Site
            </Typography>
            
            <Box component="form" onSubmit={handleSubmit} noValidate>
                <Stack spacing={3}>
                    {error && (
                        <Alert severity="error" sx={{ mb: 2 }}>
                            {error}
                        </Alert>
                    )}

                    <TextField
                        required
                        fullWidth
                        label="Site Name"
                        name="name"
                        value={formData.name}
                        onChange={handleChange}
                    />

                    <TextField
                        required
                        type="number"
                        fullWidth
                        label="Port"
                        name="port"
                        value={formData.port}
                        onChange={handleChange}
                    />

                    <TextField
                        required
                        fullWidth
                        label="Host"
                        name="host"
                        value={formData.host}
                        onChange={handleChange}
                        placeholder="Enter host domain"
                    />

                    <TextField
                        required
                        fullWidth
                        label="Frontend URL"
                        name="frontend_url"
                        value={formData.frontend_url}
                        onChange={handleChange}
                        placeholder="https://example.com"
                    />

                    <TextField
                        required
                        fullWidth
                        label="Backend URL"
                        name="backend_url"
                        value={formData.backend_url}
                        onChange={handleChange}
                        placeholder="http://localhost:3000"
                    />

                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.xss_enabled}
                                    onChange={handleSwitchChange}
                                    name="xss_enabled"
                                />
                            }
                            label="XSS Protection"
                        />

                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.sql_enabled}
                                    onChange={handleSwitchChange}
                                    name="sql_enabled"
                                />
                            }
                            label="SQL Injection Protection"
                        />

                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.vt_enabled}
                                    onChange={handleSwitchChange}
                                    name="vt_enabled"
                                />
                            }
                            label="Enable VirusTotal Scan"
                        />
                    </Box>

                    <Button
                        type="submit"
                        variant="contained"
                        color="primary"
                        size="large"
                    >
                        Add Site
                    </Button>
                </Stack>
            </Box>
        </Paper>
    );
}
