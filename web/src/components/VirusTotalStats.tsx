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
export const API_URL = '/api';

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
            const token = localStorage.getItem('token');
            const response =await fetch(`${API_URL}/vt-cache-stats`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                throw new Error('Cache istatistikleri alınamadı');
            }

            const data = await response.json();
            setStats(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Bilinmeyen hata');
        } finally {
            setLoading(false);
        }
    };

    const handleCleanup = async () => {
        setCleanupLoading(true);
        
        try {
            const token = localStorage.getItem('token');
            const response = await fetch(`${API_URL}/vt-cache-cleanup`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                throw new Error('Cache temizliği başarısız');
            }

            const result: CleanupResult = await response.json();
            setSnackbarMessage(`${result.cleaned_entries} cache girişi temizlendi`);
            setSnackbarOpen(true);
            
            // Refresh stats after cleanup
            await fetchStats();
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Cache temizleme hatası');
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
                        <Typography variant="h6">VirusTotal Cache İstatistikleri</Typography>
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
                        <Typography variant="h6">VirusTotal Cache İstatistikleri</Typography>
                    </Box>
                    <Alert severity="error">
                        <Typography>{error}</Typography>
                        <Button onClick={fetchStats} size="small" startIcon={<RefreshIcon />}>
                            Tekrar Dene
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
                            <Typography variant="h6">VirusTotal Cache İstatistikleri</Typography>
                        </Box>
                        <Box display="flex" gap={1}>
                            <Button
                                variant="outlined"
                                size="small"
                                onClick={fetchStats}
                                disabled={loading}
                                startIcon={<RefreshIcon />}
                            >
                                Yenile
                            </Button>
                            <Button
                                variant="outlined"
                                size="small"
                                onClick={handleCleanup}
                                disabled={cleanupLoading}
                                startIcon={<CleanupIcon />}
                                color="warning"
                            >
                                Cache Temizle
                            </Button>
                        </Box>
                    </Box>

                    <Typography variant="body2" color="text.secondary" mb={2}>
                        Tarih: {stats.date}
                    </Typography>

                    <Box display="flex" flexWrap="wrap" gap={2}>
                        <Box flex="1" minWidth="200px" textAlign="center" p={2} bgcolor="background.paper" borderRadius={1}>
                            <Typography variant="h4" color="primary">
                                {stats.total_entries}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                                Toplam IP Girişi
                            </Typography>
                        </Box>

                        <Box flex="1" minWidth="200px" textAlign="center" p={2} bgcolor="background.paper" borderRadius={1}>
                            <Typography variant="h4" color="error">
                                {stats.malicious_count}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                                Kötü Amaçlı IP
                            </Typography>
                            <Chip 
                                icon={<ErrorIcon />}
                                label={`%${maliciousPercentage}`}
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
                                Temiz IP
                            </Typography>
                            <Chip 
                                icon={<CheckIcon />}
                                label={`%${cleanPercentage}`}
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
                                Hatalı Giriş
                            </Typography>
                        </Box>
                    </Box>

                    <Divider sx={{ my: 2 }} />

                    <Box display="flex" gap={2} justifyContent="center">
                        <Button
                            variant="contained"
                            color="primary"
                            startIcon={<ManageIcon />}
                            onClick={handleIPManagement}
                        >
                            IP Yönetimi
                        </Button>
                        <Button
                            variant="outlined"
                            color="secondary"
                            startIcon={<RefreshIcon />}
                            onClick={fetchStats}
                        >
                            Yenile
                        </Button>
                        <Button
                            variant="outlined"
                            color="error"
                            startIcon={<CleanupIcon />}
                            onClick={handleCleanup}
                        >
                            Cache Temizle
                        </Button>
                    </Box>

                    <Divider sx={{ my: 2 }} />

                    <Alert severity="info" icon={<SecurityIcon />}>
                        <Typography variant="body2">
                            VirusTotal cache sistemi günlük olarak IP adreslerini kontrol eder ve 
                            sonuçları saklar. Bu sayede aynı IP'den gelen isteklerde tekrar sorgu 
                            yapılmaz ve sistem performansı artar.
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
