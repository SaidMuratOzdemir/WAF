import React, { useEffect, useState } from 'react';
import { getBannedIPs, getCleanIPs, banIP, unbanIP, IPInfo } from '../api/ips';
import { Box, Typography, Button, TextField, List, ListItem, ListItemText, Divider, Stack } from '@mui/material';

const IPManagement: React.FC = () => {
  const [bannedIPs, setBannedIPs] = useState<IPInfo[]>([]);
  const [cleanIPs, setCleanIPs] = useState<IPInfo[]>([]);
  const [newIP, setNewIP] = useState('');
  const [error, setError] = useState<string | null>(null);

  const fetchIPs = async () => {
    try {
      setBannedIPs(await getBannedIPs());
      setCleanIPs(await getCleanIPs());
    } catch (e: any) {
      setError(e.message);
    }
  };

  useEffect(() => {
    fetchIPs();
  }, []);

  const handleBan = async (ip: string) => {
    await banIP(ip);
    fetchIPs();
  };
  const handleUnban = async (ip: string) => {
    await unbanIP(ip);
    fetchIPs();
  };
  const handleAddIP = async () => {
    if (!newIP) return;
    await banIP(newIP);
    setNewIP('');
    fetchIPs();
  };

  return (
    <Box>
      <Typography variant="h5" gutterBottom>IP Yönetimi</Typography>
      {error && <Typography color="error">{error}</Typography>}
      <Stack direction="row" spacing={2} mb={2}>
        <TextField label="IP adresi" value={newIP} onChange={e => setNewIP(e.target.value)} size="small" />
        <Button variant="contained" onClick={handleAddIP}>Banla</Button>
      </Stack>
      <Divider sx={{ my: 2 }} />
      <Typography variant="h6">Yasaklı IP'ler</Typography>
      <List>
        {bannedIPs.map(ip => (
          <ListItem key={ip.ip} secondaryAction={
            <Stack direction="row" spacing={1}>
              <Button size="small" onClick={() => handleUnban(ip.ip)}>Unban</Button>
            </Stack>
          }>
            <ListItemText primary={ip.ip} secondary={ip.banned_at && `Banned at: ${ip.banned_at}`} />
          </ListItem>
        ))}
      </List>
      <Divider sx={{ my: 2 }} />
      <Typography variant="h6">Whitelist IP'ler</Typography>
      <List>
        {cleanIPs.map(ip => (
          <ListItem key={ip.ip}>
            <ListItemText primary={ip.ip} secondary={ip.added_at && `Added at: ${ip.added_at}`} />
          </ListItem>
        ))}
      </List>
    </Box>
  );
};

export default IPManagement;
