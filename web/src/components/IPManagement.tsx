import React, { useEffect, useState, useMemo } from 'react';
import {
  Box,
  Container,
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
import { getBannedIPs, getCleanIPs, banIP, unbanIP, addCleanIP, removeCleanIP, IPInfo } from '../api/ips';

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
      setSnackbar({ open: true, message: err.message || 'Load error', severity: 'error' });
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
      setSnackbar({ open: true, message: 'Invalid IP address.', severity: 'error' });
      return;
    }
    setLoading(true);
    try {
      await banIP(ip);
      setSnackbar({ open: true, message: `${ip} successfully banned.`, severity: 'success' });
      fetchIPs();
      setNewIP('');
    } catch (err: any) {
      setSnackbar({ open: true, message: err.message || 'Ban error', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleUnban = async (ip: string) => {
    setLoading(true);
    try {
      await unbanIP(ip);
      setSnackbar({ open: true, message: `${ip} unbanned.`, severity: 'success' });
      fetchIPs();
    } catch (err: any) {
      setSnackbar({ open: true, message: err.message || 'Unban error', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleWhitelistAdd = async (ip: string) => {
    if (!ipRegex.test(ip)) {
      setSnackbar({ open: true, message: 'Invalid IP address.', severity: 'error' });
      return;
    }
    setLoading(true);
    try {
      await addCleanIP(ip);
      setSnackbar({ open: true, message: `${ip} added to whitelist.`, severity: 'success' });
      fetchIPs();
      setNewIP('');
    } catch (err: any) {
      setSnackbar({ open: true, message: err.message || 'Whitelist error', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleWhitelistRemove = async (ip: string) => {
    setLoading(true);
    try {
      await removeCleanIP(ip);
      setSnackbar({ open: true, message: `${ip} removed from whitelist.`, severity: 'success' });
      fetchIPs();
    } catch (err: any) {
      setSnackbar({ open: true, message: err.message || 'Remove whitelist error', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h3" gutterBottom>
        IP Management
      </Typography>

      <Box
        display="flex"
        flexWrap="wrap"
        alignItems="center"
        gap={2}
        sx={{ mb: 3 }}
      >
        <Box flex={1} minWidth={280}>
          <TextField
            fullWidth
            label="Add new IP"
            placeholder="e.g. 192.168.0.1"
            value={newIP}
            onChange={(e) => setNewIP(e.target.value)}
            size="medium"
          />
        </Box>
        <Box>
          <Button
            variant="contained"
            onClick={() => handleBan(newIP)}
            disabled={loading}
            size="large"
          >
            Ban
          </Button>
        </Box>
        <Box>
          <Button
            variant="outlined"
            onClick={() => handleWhitelistAdd(newIP)}
            disabled={loading}
            size="large"
          >
            Whitelist
          </Button>
        </Box>
        <Box flex={1} minWidth={280}>
          <TextField
            fullWidth
            label="Search IP"
            placeholder="Enter IP to filter"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            size="medium"
          />
        </Box>
      </Box>

      {loading && (
        <Box display="flex" justifyContent="center" my={6}>
          <CircularProgress size={80} />
        </Box>
      )}

      <Box
        display="grid"
        gridTemplateColumns={{ xs: '1fr', md: '1fr 1fr' }}
        gap={3}
      >
        <Paper elevation={4} sx={{ p: 4 }}>
            <Typography variant="h5" gutterBottom>
              Banned IPs ({filteredBans.length})
            </Typography>
            {!loading && filteredBans.length === 0 ? (
              <Typography sx={{ fontSize: '1.1rem' }}>No matching banned IPs.</Typography>
            ) : (
              <Table size="medium">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 'bold' }}>IP Address</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Banned At</TableCell>
                    <TableCell align="right" sx={{ fontWeight: 'bold' }}>Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredBans.map((ip) => (
                    <TableRow key={ip.ip} hover>
                      <TableCell>{ip.ip}</TableCell>
                      <TableCell>
                        {ip.banned_at ? new Date(ip.banned_at).toLocaleString('en-US', { hour12: false }) : '-'}
                      </TableCell>
                      <TableCell align="right">
                        <Button
                          variant="outlined"
                          onClick={() => handleUnban(ip.ip)}
                          disabled={loading}
                        >
                          Unban
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Paper>

        <Paper elevation={4} sx={{ p: 4 }}>
            <Typography variant="h5" gutterBottom>
              Whitelist IPs ({filteredCleans.length})
            </Typography>
            {!loading && filteredCleans.length === 0 ? (
              <Typography sx={{ fontSize: '1.1rem' }}>No matching whitelist IPs.</Typography>
            ) : (
              <Table size="medium">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 'bold' }}>IP Address</TableCell>
                    <TableCell sx={{ fontWeight: 'bold' }}>Added At</TableCell>
                    <TableCell align="right" sx={{ fontWeight: 'bold' }}>Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredCleans.map((ip) => (
                    <TableRow key={ip.ip} hover>
                      <TableCell>{ip.ip}</TableCell>
                      <TableCell>
                        {ip.added_at ? new Date(ip.added_at).toLocaleString('en-US', { hour12: false }) : '-'}
                      </TableCell>
                      <TableCell align="right">
                        <Button
                          variant="outlined"
                          color="error"
                          onClick={() => handleWhitelistRemove(ip.ip)}
                          disabled={loading}
                        >
                          Remove
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Paper>
      </Box>

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
