// web/src/components/RequestLogs.tsx

import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
  TextField,
  Button,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
  Card,
  CardContent,
  Alert,
  CircularProgress,
  Tooltip
} from '@mui/material';
import {
  Visibility as VisibilityIcon,
  Delete as DeleteIcon,
  FilterList as FilterIcon,
  Refresh as RefreshIcon
} from '@mui/icons-material';
import { getRecentRequests, getRequestDetails, deleteRequest, RequestLog, RequestDetails } from '../api/logs';

interface RequestLogsProps {
  siteName?: string;
}

export default function RequestLogs({ siteName }: RequestLogsProps) {
  const [logs, setLogs] = useState<RequestLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedRequest, setSelectedRequest] = useState<RequestDetails | null>(null);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [filters, setFilters] = useState({
    limit: 100,
    site_name: siteName || '',
    client_ip: '',
    method: '',
    blocked_only: false
  });

  const loadLogs = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await getRecentRequests(filters);
      setLogs(response.requests);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Logs yüklenirken hata oluştu');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, [filters]);

  const handleViewDetails = async (requestId: string) => {
    try {
      const details = await getRequestDetails(requestId);
      setSelectedRequest(details);
      setDetailDialogOpen(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Detaylar yüklenirken hata oluştu');
    }
  };

  const handleDeleteRequest = async (requestId: string) => {
    if (!window.confirm('Bu isteği silmek istediğinizden emin misiniz?')) {
      return;
    }
    
    try {
      await deleteRequest(requestId);
      setLogs(logs.filter(log => log.request_id !== requestId));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Silme işlemi başarısız');
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('tr-TR');
  };

  const getStatusColor = (log: RequestLog) => {
    if (log.is_blocked) return 'error';
    return 'default';
  };

  const truncateText = (text: string, maxLength: number = 50) => {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
  };

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        İstek Logları
      </Typography>

      {/* Filters */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} sm={3}>
            <TextField
              fullWidth
              label="IP Adresi"
              value={filters.client_ip}
              onChange={(e) => setFilters({ ...filters, client_ip: e.target.value })}
              size="small"
            />
          </Grid>
          <Grid item xs={12} sm={2}>
            <FormControl fullWidth size="small">
              <InputLabel>HTTP Metodu</InputLabel>
              <Select
                value={filters.method}
                onChange={(e) => setFilters({ ...filters, method: e.target.value })}
                label="HTTP Metodu"
              >
                <MenuItem value="">Tümü</MenuItem>
                <MenuItem value="GET">GET</MenuItem>
                <MenuItem value="POST">POST</MenuItem>
                <MenuItem value="PUT">PUT</MenuItem>
                <MenuItem value="DELETE">DELETE</MenuItem>
                <MenuItem value="PATCH">PATCH</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} sm={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Limit</InputLabel>
              <Select
                value={filters.limit}
                onChange={(e) => setFilters({ ...filters, limit: e.target.value as number })}
                label="Limit"
              >
                <MenuItem value={50}>50</MenuItem>
                <MenuItem value={100}>100</MenuItem>
                <MenuItem value={200}>200</MenuItem>
                <MenuItem value={500}>500</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} sm={2}>
            <Button
              variant={filters.blocked_only ? "contained" : "outlined"}
              color="error"
              onClick={() => setFilters({ ...filters, blocked_only: !filters.blocked_only })}
              startIcon={<FilterIcon />}
              fullWidth
            >
              Sadece Bloklananlar
            </Button>
          </Grid>
          <Grid item xs={12} sm={3}>
            <Button
              variant="outlined"
              onClick={loadLogs}
              startIcon={<RefreshIcon />}
              fullWidth
            >
              Yenile
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {loading ? (
        <Box display="flex" justifyContent="center" p={3}>
          <CircularProgress />
        </Box>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Zaman</TableCell>
                <TableCell>IP</TableCell>
                <TableCell>Site</TableCell>
                <TableCell>Metod</TableCell>
                <TableCell>Path</TableCell>
                <TableCell>Durum</TableCell>
                <TableCell>İşlemler</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {logs.map((log) => (
                <TableRow key={log.request_id} hover>
                  <TableCell>{formatTimestamp(log.timestamp)}</TableCell>
                  <TableCell>{log.client_ip}</TableCell>
                  <TableCell>{log.site_name}</TableCell>
                  <TableCell>
                    <Chip 
                      label={log.method} 
                      size="small" 
                      color="primary" 
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell>
                    <Tooltip title={log.path}>
                      <Typography variant="body2">
                        {truncateText(log.path, 30)}
                      </Typography>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    {log.is_blocked ? (
                      <Chip 
                        label={`Bloklandı: ${log.block_reason}`} 
                        color="error" 
                        size="small"
                      />
                    ) : (
                      <Chip 
                        label="Başarılı" 
                        color="success" 
                        size="small"
                      />
                    )}
                  </TableCell>
                  <TableCell>
                    <Tooltip title="Detayları Görüntüle">
                      <IconButton
                        size="small"
                        onClick={() => handleViewDetails(log.request_id)}
                      >
                        <VisibilityIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Sil">
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => handleDeleteRequest(log.request_id)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Detail Dialog */}
      <Dialog
        open={detailDialogOpen}
        onClose={() => setDetailDialogOpen(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle>İstek Detayları</DialogTitle>
        <DialogContent>
          {selectedRequest && (
            <Box>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Card>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        İstek Bilgileri
                      </Typography>
                      <Typography><strong>IP:</strong> {selectedRequest.request.client_ip}</Typography>
                      <Typography><strong>Site:</strong> {selectedRequest.request.site_name}</Typography>
                      <Typography><strong>Metod:</strong> {selectedRequest.request.method}</Typography>
                      <Typography><strong>Path:</strong> {selectedRequest.request.path}</Typography>
                      <Typography><strong>Query:</strong> {selectedRequest.request.query_string}</Typography>
                      <Typography><strong>User Agent:</strong> {selectedRequest.request.user_agent}</Typography>
                      <Typography><strong>Content Type:</strong> {selectedRequest.request.content_type}</Typography>
                      <Typography><strong>Content Length:</strong> {selectedRequest.request.content_length}</Typography>
                      {selectedRequest.request.is_blocked && (
                        <Typography color="error">
                          <strong>Blok Nedeni:</strong> {selectedRequest.request.block_reason}
                        </Typography>
                      )}
                    </CardContent>
                  </Card>
                </Grid>
                
                {selectedRequest.response && (
                  <Grid item xs={12} md={6}>
                    <Card>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>
                          Yanıt Bilgileri
                        </Typography>
                        <Typography><strong>Status Code:</strong> {selectedRequest.response.status_code}</Typography>
                        <Typography><strong>Content Type:</strong> {selectedRequest.response.content_type}</Typography>
                        <Typography><strong>Content Length:</strong> {selectedRequest.response.content_length}</Typography>
                        <Typography><strong>İşlem Süresi:</strong> {selectedRequest.response.processing_time_ms}ms</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                )}
              </Grid>

              <Box mt={2}>
                <Typography variant="h6" gutterBottom>
                  Headers
                </Typography>
                <Paper sx={{ p: 2, maxHeight: 200, overflow: 'auto' }}>
                  <pre style={{ margin: 0, fontSize: '12px' }}>
                    {JSON.stringify(selectedRequest.request.headers, null, 2)}
                  </pre>
                </Paper>
              </Box>

              {selectedRequest.request.body && (
                <Box mt={2}>
                  <Typography variant="h6" gutterBottom>
                    Request Body
                  </Typography>
                  <Paper sx={{ p: 2, maxHeight: 200, overflow: 'auto' }}>
                    <pre style={{ margin: 0, fontSize: '12px' }}>
                      {selectedRequest.request.body}
                    </pre>
                  </Paper>
                </Box>
              )}

              {selectedRequest.response?.body && (
                <Box mt={2}>
                  <Typography variant="h6" gutterBottom>
                    Response Body
                  </Typography>
                  <Paper sx={{ p: 2, maxHeight: 200, overflow: 'auto' }}>
                    <pre style={{ margin: 0, fontSize: '12px' }}>
                      {selectedRequest.response.body}
                    </pre>
                  </Paper>
                </Box>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailDialogOpen(false)}>Kapat</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
} 