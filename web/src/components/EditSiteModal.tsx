import { useState, useEffect } from 'react';
import {
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    Button,
    TextField,
    FormControlLabel,
    Switch,
    Box,
    Alert,
    CircularProgress
} from '@mui/material';
import type { Site, SiteCreate } from '../types/Site';
import { updateSite } from '../api/sites';

interface EditSiteModalProps {
    open: boolean;
    site: Site | null;
    onClose: () => void;
    onSuccess: () => void;
}

const EditSiteModal = ({ open, site, onClose, onSuccess }: EditSiteModalProps) => {
    const [formData, setFormData] = useState<SiteCreate>({
        port: 0,
        host: '',
        name: '',
        frontend_url: '',
        backend_url: '',
        xss_enabled: true,
        sql_enabled: true,
        vt_enabled: false
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Reset form when site changes
    useEffect(() => {
        if (site) {
            setFormData({
                port: site.port,
                host: site.host,
                name: site.name,
                frontend_url: site.frontend_url,
                backend_url: site.backend_url,
                xss_enabled: site.xss_enabled,
                sql_enabled: site.sql_enabled,
                vt_enabled: site.vt_enabled
            });
        }
        setError(null);
    }, [site]);

    const handleInputChange = (field: keyof SiteCreate) => (
        event: React.ChangeEvent<HTMLInputElement>
    ) => {
        const value = event.target.type === 'checkbox' 
            ? event.target.checked 
            : event.target.type === 'number' 
                ? parseInt(event.target.value) || 0
                : event.target.value;
        
        setFormData(prev => ({
            ...prev,
            [field]: value
        }));
    };

    const handleSubmit = async () => {
        if (!site) return;

        setLoading(true);
        setError(null);

        try {
            await updateSite(site.id, formData);
            onSuccess();
            onClose();
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Update failed');
        } finally {
            setLoading(false);
        }
    };

    const handleClose = () => {
        if (!loading) {
            onClose();
        }
    };

    return (
        <Dialog open={open} onClose={handleClose} maxWidth="md" fullWidth>
            <DialogTitle>
                Edit Site: {site?.name}
            </DialogTitle>
            <DialogContent>
                {error && (
                    <Alert severity="error" sx={{ mb: 2 }}>
                        {error}
                    </Alert>
                )}

                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
                    <TextField
                        label="Site Name"
                        value={formData.name}
                        onChange={handleInputChange('name')}
                        fullWidth
                        required
                        disabled={loading}
                    />

                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <TextField
                            label="Port"
                            type="number"
                            value={formData.port}
                            onChange={handleInputChange('port')}
                            required
                            disabled={loading}
                            inputProps={{ min: 1, max: 65535 }}
                        />
                        <TextField
                            label="Host"
                            value={formData.host}
                            onChange={handleInputChange('host')}
                            required
                            disabled={loading}
                            placeholder="localhost"
                            sx={{ flex: 1 }}
                        />
                    </Box>

                    <TextField
                        label="Frontend URL or IP"
                        value={formData.frontend_url}
                        onChange={handleInputChange('frontend_url')}
                        fullWidth
                        required
                        disabled={loading}
                        placeholder="http://host.docker.internal:5174/"
                    />

                    <TextField
                        label="Backend URL or IP"
                        value={formData.backend_url}
                        onChange={handleInputChange('backend_url')}
                        fullWidth
                        required
                        disabled={loading}
                        placeholder="http://host.docker.internal:8000/"
                    />

                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.xss_enabled}
                                    onChange={handleInputChange('xss_enabled')}
                                    disabled={loading}
                                />
                            }
                            label="XSS Protection"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.sql_enabled}
                                    onChange={handleInputChange('sql_enabled')}
                                    disabled={loading}
                                />
                            }
                            label="SQL Injection Protection"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.vt_enabled}
                                    onChange={handleInputChange('vt_enabled')}
                                    disabled={loading}
                                />
                            }
                            label="VirusTotal IP Check"
                        />
                    </Box>
                </Box>
            </DialogContent>
            <DialogActions>
                <Button onClick={handleClose} disabled={loading}>
                    Cancel
                </Button>
                <Button 
                    onClick={handleSubmit} 
                    variant="contained"
                    disabled={loading}
                    startIcon={loading ? <CircularProgress size={16} /> : undefined}
                >
                    {loading ? 'Updating...' : 'Update'}
                </Button>
            </DialogActions>
        </Dialog>
    );
};

export default EditSiteModal;
