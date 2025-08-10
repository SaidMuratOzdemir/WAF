import { useEffect, useState } from 'react';
import {
    Card,
    CardContent,
    Typography,
    Box,
    Button,
    Chip,
    Alert,
    CircularProgress,
    Divider,
    Snackbar
} from '@mui/material';
import {
    Security as SecurityIcon,
    Refresh as RefreshIcon,
    DeleteSweep as CleanupIcon,
    CheckCircle as CheckIcon,
    Error as ErrorIcon,
    ManageAccounts as ManageIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { apiFetch } from '../api/client';
export const API_URL = '/api/v1';

interface CacheStats {
    date: string;
    total_entries: number;
    malicious_count: number;
    clean_count: number;
    error_count: number;
}

interface CleanupResult {
    message: string;
    cleaned_entries: number;
}

const VirusTotalStats = () => {
    const [stats, setStats] = useState<CacheStats | null>(null);
    const [loading, setLoading] = useState(false);
    const [cleanupLoading, setCleanupLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [snackbarOpen, setSnackbarOpen] = useState(false);
    const [snackbarMessage, setSnackbarMessage] = useState('');

    const navigate = useNavigate();

    const fetchStats = async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await apiFetch<CacheStats>('/system/vt-cache/stats');
            setStats(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Unknown error');
        } finally {
            setLoading(false);
        }
    };

    const handleCleanup = async () => {
        setCleanupLoading(true);
        try {
            const result = await apiFetch<CleanupResult>('/system/vt-cache/cleanup', { method: 'POST' });
            setSnackbarMessage(`${result.cleaned_entries} cache entries cleaned`);
            setSnackbarOpen(true);
            await fetchStats();
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Cache cleanup error');
        } finally {
            setCleanupLoading(false);
        }
    };

    const handleIPManagement = () => {
        navigate('/ip-management');
    };

    useEffect(() => {
        fetchStats();
        
        // Auto-refresh every 5 minutes
        const interval = setInterval(fetchStats, 5 * 60 * 1000);
        return () => clearInterval(interval);
    }, []);

    if (loading && !stats) {
        return (
            <Card>
                <CardContent>
                    <Box display="flex" alignItems="center" gap={1} mb={2}>
                        <SecurityIcon />
                        <Typography variant="h6">VirusTotal Cache Statistics</Typography>
                    </Box>
                    <Box display="flex" justifyContent="center" p={2}>
                        <CircularProgress />
                    </Box>
                </CardContent>
            </Card>
        );
    }

    if (error) {
        return (
            <Card>
                <CardContent>
                    <Box display="flex" alignItems="center" gap={1} mb={2}>
                        <SecurityIcon />
                        <Typography variant="h6">VirusTotal Cache Statistics</Typography>
                    </Box>
                    <Alert severity="error">
                        <Typography>{error}</Typography>
                        <Button onClick={fetchStats} size="small" startIcon={<RefreshIcon />}>
                            Retry
                        </Button>
                    </Alert>
                </CardContent>
            </Card>
        );
    }

    if (!stats) {
        return null;
    }

    const maliciousPercentage = stats.total_entries > 0 
        ? Math.round((stats.malicious_count / stats.total_entries) * 100) 
        : 0;

    const cleanPercentage = stats.total_entries > 0 
        ? Math.round((stats.clean_count / stats.total_entries) * 100) 
        : 0;

    return (
        <>
            <Card>
                <CardContent>
                    <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                        <Box display="flex" alignItems="center" gap={1}>
                            <SecurityIcon />
                            <Typography variant="h6">VirusTotal Cache Statistics</Typography>
                        </Box>
                    </Box>

                    <Typography variant="body2" color="text.secondary" mb={2}>
                        Date: {stats.date}
                    </Typography>

                    <Box display="flex" flexWrap="wrap" gap={2}>
                        <Box flex="1" minWidth="200px" textAlign="center" p={2} bgcolor="background.paper" borderRadius={1}>
                            <Typography variant="h4" color="primary">
                                {stats.total_entries}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                                Total IP Entries
                            </Typography>
                        </Box>

                        <Box flex="1" minWidth="200px" textAlign="center" p={2} bgcolor="background.paper" borderRadius={1}>
                            <Typography variant="h4" color="error">
                                {stats.malicious_count}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                                Malicious IP
                            </Typography>
                            <Chip 
                                icon={<ErrorIcon />}
                                label={`${maliciousPercentage}%`}
                                color="error"
                                size="small"
                                sx={{ mt: 1 }}
                            />
                        </Box>

                        <Box flex="1" minWidth="200px" textAlign="center" p={2} bgcolor="background.paper" borderRadius={1}>
                            <Typography variant="h4" color="success.main">
                                {stats.clean_count}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                                Clean IP
                            </Typography>
                            <Chip 
                                icon={<CheckIcon />}
                                label={`${cleanPercentage}%`}
                                color="success"
                                size="small"
                                sx={{ mt: 1 }}
                            />
                        </Box>

                        <Box flex="1" minWidth="200px" textAlign="center" p={2} bgcolor="background.paper" borderRadius={1}>
                            <Typography variant="h4" color="warning.main">
                                {stats.error_count}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                                Error Entries
                            </Typography>
                        </Box>
                    </Box>

                    <Divider sx={{ my: 2 }} />

                    <Box display="flex" gap={2} justifyContent="center">
                        <Button
                            variant="contained"
                            color="primary"
                            startIcon={<SecurityIcon />}
                            onClick={() => navigate('/patterns')}
                        >
                            Validation Patterns
                        </Button>

                        <Button
                            variant="contained"
                            color="primary"
                            startIcon={<ManageIcon />}
                            onClick={handleIPManagement}
                        >
                            IP Management
                        </Button>
                        <Button
                            variant="contained"
                            color="primary"
                            startIcon={<SecurityIcon />}
                            onClick={() => navigate('/logs')}
                        >
                            Logs
                        </Button>

                        <Button
                            variant="outlined"
                            color="secondary"
                            startIcon={<RefreshIcon />}
                            onClick={fetchStats}
                        >
                            Refresh
                        </Button>
                        <Button
                            variant="outlined"
                            color="error"
                            startIcon={cleanupLoading ? <CircularProgress size={16} /> : <CleanupIcon />}
                            onClick={handleCleanup}
                            disabled={cleanupLoading}
                        >
                            {cleanupLoading ? 'Cleaning...' : 'Clean Cache'}
                        </Button>
                    </Box>

                    <Divider sx={{ my: 2 }} />

                    <Alert severity="info" icon={<SecurityIcon />}>
                        <Typography variant="body2">
                            The VirusTotal cache system checks IP addresses daily and stores the results. This avoids repeat lookups for requests from the same IP and improves performance.
                        </Typography>
                    </Alert>

                    {loading && (
                        <Box display="flex" justifyContent="center" mt={2}>
                            <CircularProgress size={20} />
                        </Box>
                    )}
                </CardContent>
            </Card>

            <Snackbar
                open={snackbarOpen}
                autoHideDuration={4000}
                onClose={() => setSnackbarOpen(false)}
                message={snackbarMessage}
            />
        </>
    );
};

export default VirusTotalStats;
