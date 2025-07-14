import React, { useEffect, useState } from 'react';
import { Pattern, PatternCreate, PatternUpdate } from '../types/Pattern';
import { getPatterns, addPattern, addPatternsFromTxt, updatePattern, deletePattern } from '../api/patterns';
import { Box, Typography, Button, TextField, Select, MenuItem, Dialog, DialogTitle, DialogContent, DialogActions, List, ListItem, ListItemText, IconButton, Snackbar, Alert, Stack, InputLabel } from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';

const patternTypes = ['xss', 'sql', 'custom'];

const PatternManagement: React.FC = () => {
  const [patterns, setPatterns] = useState<Pattern[]>([]);
  const [filter, setFilter] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [openEdit, setOpenEdit] = useState(false);
  const [editPattern, setEditPattern] = useState<Pattern | null>(null);
  const [editForm, setEditForm] = useState<PatternUpdate>({});
  const [snackbar, setSnackbar] = useState<string | null>(null);
  const [newPattern, setNewPattern] = useState<PatternCreate>({ pattern: '', type: 'xss', description: '' });
  const [txtFile, setTxtFile] = useState<File | null>(null);

  const fetchPatterns = async () => {
    setLoading(true);
    try {
      setPatterns(await getPatterns(filter || undefined));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchPatterns(); }, [filter]);

  const handleAddPattern = async () => {
    if (!newPattern.pattern.trim()) return;
    try {
      await addPattern(newPattern);
      setSnackbar('Pattern eklendi');
      setNewPattern({ pattern: '', type: 'xss', description: '' });
      fetchPatterns();
    } catch (e: any) {
      setError(e.message);
    }
  };

  const handleTxtUpload = async () => {
    if (!txtFile) return;
    try {
      await addPatternsFromTxt(txtFile, filter || 'custom');
      setSnackbar('TXT ile patternler eklendi');
      setTxtFile(null);
      fetchPatterns();
    } catch (e: any) {
      setError(e.message);
    }
  };

  const handleEdit = (pattern: Pattern) => {
    setEditPattern(pattern);
    setEditForm({ pattern: pattern.pattern, type: pattern.type, description: pattern.description });
    setOpenEdit(true);
  };

  const handleEditSave = async () => {
    if (!editPattern) return;
    try {
      await updatePattern(editPattern.id, editForm);
      setSnackbar('Pattern güncellendi');
      setOpenEdit(false);
      fetchPatterns();
    } catch (e: any) {
      setError(e.message);
    }
  };

  const handleDelete = async (id: number) => {
    if (!window.confirm('Silmek istediğinize emin misiniz?')) return;
    try {
      await deletePattern(id);
      setSnackbar('Pattern silindi');
      fetchPatterns();
    } catch (e: any) {
      setError(e.message);
    }
  };

  return (
    <Box p={2}>
      <Typography variant="h5" mb={2}>Pattern Yönetimi</Typography>
      <Stack direction="row" spacing={2} mb={2} alignItems="center">
        <InputLabel>Filtre:</InputLabel>
        <Select value={filter} onChange={e => setFilter(e.target.value)} size="small" sx={{ minWidth: 120 }}>
          <MenuItem value="">Tümü</MenuItem>
          {patternTypes.map(t => <MenuItem key={t} value={t}>{t.toUpperCase()}</MenuItem>)}
        </Select>
        <TextField label="Yeni Pattern" value={newPattern.pattern} onChange={e => setNewPattern({ ...newPattern, pattern: e.target.value })} size="small" />
        <Select value={newPattern.type} onChange={e => setNewPattern({ ...newPattern, type: e.target.value })} size="small">
          {patternTypes.map(t => <MenuItem key={t} value={t}>{t.toUpperCase()}</MenuItem>)}
        </Select>
        <TextField label="Açıklama" value={newPattern.description} onChange={e => setNewPattern({ ...newPattern, description: e.target.value })} size="small" />
        <Button variant="contained" onClick={handleAddPattern}>Ekle</Button>
        <input type="file" accept=".txt" style={{ display: 'none' }} id="txt-upload" onChange={e => setTxtFile(e.target.files?.[0] || null)} />
        <label htmlFor="txt-upload">
          <Button variant="outlined" component="span">TXT Yükle</Button>
        </label>
        <Button variant="contained" color="secondary" onClick={handleTxtUpload} disabled={!txtFile}>TXT ile Ekle</Button>
      </Stack>
      <List>
        {patterns.map(p => (
          <ListItem key={p.id} secondaryAction={
            <>
              <IconButton edge="end" onClick={() => handleEdit(p)}><EditIcon /></IconButton>
              <IconButton edge="end" color="error" onClick={() => handleDelete(p.id)}><DeleteIcon /></IconButton>
            </>
          }>
            <ListItemText primary={p.pattern} secondary={`${p.type.toUpperCase()}${p.description ? ' - ' + p.description : ''}`} />
          </ListItem>
        ))}
      </List>
      <Dialog open={openEdit} onClose={() => setOpenEdit(false)}>
        <DialogTitle>Pattern Güncelle</DialogTitle>
        <DialogContent>
          <TextField label="Pattern" value={editForm.pattern || ''} onChange={e => setEditForm(f => ({ ...f, pattern: e.target.value }))} fullWidth margin="dense" />
          <Select value={editForm.type || ''} onChange={e => setEditForm(f => ({ ...f, type: e.target.value }))} fullWidth margin="dense">
            {patternTypes.map(t => <MenuItem key={t} value={t}>{t.toUpperCase()}</MenuItem>)}
          </Select>
          <TextField label="Açıklama" value={editForm.description || ''} onChange={e => setEditForm(f => ({ ...f, description: e.target.value }))} fullWidth margin="dense" />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenEdit(false)}>İptal</Button>
          <Button onClick={handleEditSave} variant="contained">Kaydet</Button>
        </DialogActions>
      </Dialog>
      <Snackbar open={!!snackbar} autoHideDuration={3000} onClose={() => setSnackbar(null)}>
        <Alert severity="success">{snackbar}</Alert>
      </Snackbar>
      <Snackbar open={!!error} autoHideDuration={4000} onClose={() => setError(null)}>
        <Alert severity="error">{error}</Alert>
      </Snackbar>
    </Box>
  );
};

export default PatternManagement; 