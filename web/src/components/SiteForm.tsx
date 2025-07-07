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
        port: 8081,
        name: '',
        frontend_url: '',
        backend_url: '',
        xss_enabled: true,
        sql_enabled: true
    });
    const [error, setError] = useState<string>('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            // Validate port range
            if (formData.port < 1024 || formData.port > 65535) {
                throw new Error('Port must be between 1024 and 65535');
            }
            
            // Validate URLs
            try {
                new URL(formData.frontend_url);
                new URL(formData.backend_url);
            } catch {
                throw new Error('Please enter valid URLs');
            }

            const site = await addSite(formData);
            console.log('Site added successfully:', site);
            onSiteAdded();
            console.log('onSiteAdded called');
            
            // Reset form
            setFormData({
                port: 8081,
                name: '',
                frontend_url: '',
                backend_url: '',
                xss_enabled: true,
                sql_enabled: true
            });
            setError('');
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Failed to add site');
        }
    };

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value, type, checked } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: type === 'checkbox' ? checked : value
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
                        inputProps={{ min: 1024, max: 65535 }}
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
                                    onChange={handleChange}
                                    name="xss_enabled"
                                />
                            }
                            label="XSS Protection"
                        />

                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.sql_enabled}
                                    onChange={handleChange}
                                    name="sql_enabled"
                                />
                            }
                            label="SQL Injection Protection"
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
