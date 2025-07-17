import React, { useEffect, useState, useMemo } from 'react';
import {
  Box,
  Container,
  Grid,
  Paper,
  Typography,
  Button,
  TextField,
  Table,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  CircularProgress,
  Snackbar,
  Alert,
} from '@mui/material';
import { getBannedIPs, getCleanIPs, banIP, unbanIP, IPInfo } from '../api/ips';

const ipRegex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$/;

const IPManagement: React.FC = () => {
  const [bannedIPs, setBannedIPs] = useState<IPInfo[]>([]);
  const [cleanIPs, setCleanIPs] = useState<IPInfo[]>([]);
  const [newIP, setNewIP] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error'; }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const fetchIPs = async () => {
    setLoading(true);
    try {
      const [bans, cleans] = await Promise.all([getBannedIPs(), getCleanIPs()]);
      setBannedIPs(bans);
      setCleanIPs(cleans);
    } catch (err: any) {
      setSnackbar({ open: true, message: err.message || 'Yükleme hatası', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIPs();
  }, []);

  const filteredBans = useMemo(
    () => bannedIPs.filter((ip) => ip.ip.includes(search)),
    [bannedIPs, search]
  );
  const filteredCleans = useMemo(
    () => cleanIPs.filter((ip) => ip.ip.includes(search)),
    [cleanIPs, search]
  );

  const handleBan = async (ip: string) => {
    if (!ipRegex.test(ip)) {
      setSnackbar({ open: true, message: 'Geçersiz IP adresi.', severity: 'error' });
      return;
    }
    setLoading(true);
    try {
      await banIP(ip);
      setSnackbar({ open: true, message: `${ip} başarıyla yasaklandı.`, severity: 'success' });
      fetchIPs();
      setNewIP('');
    } catch (err: any) {
      setSnackbar({ open: true, message: err.message || 'Banlama hatası', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleUnban = async (ip: string) => {
    setLoading(true);
    try {
      await unbanIP(ip);
      setSnackbar({ open: true, message: `${ip} yasağı kaldırıldı.`, severity: 'success' });
      fetchIPs();
    } catch (err: any) {
      setSnackbar({ open: true, message: err.message || 'Unban hatası', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h3" gutterBottom>
        IP Yönetimi
      </Typography>

      <Grid container spacing={2} alignItems="center" sx={{ mb: 3 }}>
        <Grid item xs={12} sm={8} md={5}>
          <TextField
            fullWidth
            label="Yeni IP ekle"
            placeholder="Ör: 192.168.0.1"
            value={newIP}
            onChange={(e) => setNewIP(e.target.value)}
            size="medium"
          />
        </Grid>
        <Grid item xs={12} sm={4} md={2}>
          <Button
            fullWidth
            variant="contained"
            onClick={() => handleBan(newIP)}
            disabled={loading}
            size="large"
          >
            Banla
          </Button>
        </Grid>
        <Grid item xs={12} sm={12} md={5}>
          <TextField
            fullWidth
            label="Ara IP"
            placeholder="Filtrelemek için IP girin"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            size="medium"
          />
        </Grid>
      </Grid>

      {loading && (
        <Box display="flex" justifyContent="center" my={6}>
          <CircularProgress size={80} />
        </Box>
      )}

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper elevation={4} sx={{ p: 4 }}>
            <Typography variant="h5" gutterBottom>
              Yasaklı IP'ler ({filteredBans.length})
            </Typography>
            {!loading && filteredBans.length === 0 ? (
              <Typography sx={{ fontSize: '1.1rem' }}>Eşleşen yasaklı IP yok.</Typography>
            ) : (
              <Table size="medium">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 'bold' }}>IP Adresi</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Banned At</TableCell>
                    <TableCell align="right" sx={{ fontWeight: 'bold' }}>İşlem</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredBans.map((ip) => (
                    <TableRow key={ip.ip} hover>
                      <TableCell>{ip.ip}</TableCell>
                      <TableCell>
                        {ip.banned_at ? new Date(ip.banned_at).toLocaleString('tr-TR', { hour12: false }) : '-'}
                      </TableCell>
                      <TableCell align="right">
                        <Button
                          variant="outlined"
                          onClick={() => handleUnban(ip.ip)}
                          disabled={loading}
                        >
                          Kaldır
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper elevation={4} sx={{ p: 4 }}>
            <Typography variant="h5" gutterBottom>
              Whitelist IP'ler ({filteredCleans.length})
            </Typography>
            {!loading && filteredCleans.length === 0 ? (
              <Typography sx={{ fontSize: '1.1rem' }}>Eşleşen whitelist IP yok.</Typography>
            ) : (
              <Table size="medium">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 'bold' }}>IP Adresi</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Added At</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredCleans.map((ip) => (
                    <TableRow key={ip.ip} hover>
                      <TableCell>{ip.ip}</TableCell>
                      <TableCell>
                        {ip.added_at ? new Date(ip.added_at).toLocaleString('tr-TR', { hour12: false }) : '-'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Paper>
        </Grid>
      </Grid>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert onClose={() => setSnackbar({ ...snackbar, open: false })} severity={snackbar.severity}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default IPManagement;
