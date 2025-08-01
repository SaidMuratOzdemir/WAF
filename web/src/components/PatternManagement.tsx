import React, { useEffect, useState, useMemo } from 'react';
import {
  Box, Typography, Button, TextField, Select, MenuItem, Dialog, DialogTitle, DialogContent, DialogActions,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, IconButton, Snackbar, Alert, Stack,
  InputAdornment, Chip, CircularProgress, Tooltip, Pagination
} from '@mui/material';
import { Add, Delete, Edit, UploadFile, Search } from '@mui/icons-material';
import { useForm, Controller } from 'react-hook-form';
import { useDropzone } from 'react-dropzone';
import debounce from 'lodash.debounce';
import { Pattern, PatternCreate, PatternUpdate, PatternType } from '../types/Pattern';
import { getPatterns, addPattern, addPatternsFromTxt, updatePattern, deletePattern, PatternUploadResult } from '../api/patterns';

const patternTypes = [
  { value: PatternType.XSS, label: 'XSS', color: 'error' },
  { value: PatternType.SQL, label: 'SQL', color: 'primary' },
  { value: PatternType.CUSTOM, label: 'CUSTOM', color: 'default' },
];

const defaultFormValues = { pattern: '', type: PatternType.CUSTOM, description: '' };

type PatternFormData = PatternCreate;

const PatternManagement: React.FC = () => {
  const [patterns, setPatterns] = useState<Pattern[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [filter, setFilter] = useState<PatternType | ''>('');
  const [search, setSearch] = useState('');
  const [searchDebounced, setSearchDebounced] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [openAdd, setOpenAdd] = useState(false);
  const [openEdit, setOpenEdit] = useState(false);
  const [editPattern, setEditPattern] = useState<Pattern | null>(null);
  const [openUpload, setOpenUpload] = useState(false);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({ open: false, message: '', severity: 'success' });
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<PatternUploadResult | null>(null);
  const [txtFile, setTxtFile] = useState<File | null>(null);
  const [openDelete, setOpenDelete] = useState<{ open: boolean; id: number | null }>({ open: false, id: null });
  const [uploadPatternType, setUploadPatternType] = useState<PatternType>(PatternType.CUSTOM);

  // react-hook-form
  const { control, handleSubmit, reset } = useForm<PatternFormData>({ defaultValues: defaultFormValues });
  const { control: editControl, handleSubmit: handleEditSubmit, reset: resetEdit } = useForm<PatternFormData>({ defaultValues: defaultFormValues });

  // Dosya yükleme
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop: (files: File[]) => setTxtFile(files[0]),
    accept: { 'text/plain': ['.txt'] },
    multiple: false
  });

  // Debounced search
  const debouncedSetSearch = useMemo(() => debounce((val: string) => setSearchDebounced(val), 400), []);
  useEffect(() => { debouncedSetSearch(search); }, [search, debouncedSetSearch]);

  // Patternleri çek
  const fetchPatterns = async (pageArg = page, pageSizeArg = pageSize, filterArg = filter, searchArg = searchDebounced) => {
    setLoading(true);
    try {
      const res = await getPatterns(pageArg, pageSizeArg, filterArg || undefined, searchArg || undefined);
      setPatterns(res.items);
      setTotal(res.total);
      setError(null);
    } catch (e: any) {
      setError(e.message || 'Veri alınamadı.');
      setPatterns([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchPatterns(1, pageSize, filter, searchDebounced); setPage(1); }, [filter, pageSize, searchDebounced]);
  useEffect(() => { fetchPatterns(page, pageSize, filter, searchDebounced); }, [page]);

  // Pattern ekle
  const onAdd = async (data: PatternFormData) => {
    try {
      // type alanı enumdan gelmeli
      await addPattern({ ...data, type: data.type as PatternType });
      setSnackbar({ open: true, message: 'Pattern başarıyla eklendi.', severity: 'success' });
      setOpenAdd(false);
      reset(defaultFormValues);
      fetchPatterns();
    } catch (e: any) {
      setSnackbar({ open: true, message: e.message || JSON.stringify(e), severity: 'error' });
    }
  };

  // Pattern güncelle
  const onEdit = async (data: PatternFormData) => {
    if (!editPattern) return;
    try {
      await updatePattern(editPattern.id, { ...data, type: data.type as PatternType });
      setSnackbar({ open: true, message: 'Pattern güncellendi.', severity: 'success' });
      setOpenEdit(false);
      setEditPattern(null);
      fetchPatterns();
    } catch (e: any) {
      setSnackbar({ open: true, message: e.message || JSON.stringify(e), severity: 'error' });
    }
  };

  // Pattern sil
  const onDelete = async () => {
    if (!openDelete.id) return;
    try {
      await deletePattern(openDelete.id);
      setSnackbar({ open: true, message: 'Pattern silindi.', severity: 'success' });
      setOpenDelete({ open: false, id: null });
      fetchPatterns();
    } catch (e: any) {
      setSnackbar({ open: true, message: e.message || 'Pattern silinemedi.', severity: 'error' });
    }
  };

  // Dosya ile yükleme
  const handleTxtUpload = async () => {
    if (!txtFile) return;
    setUploading(true);
    try {
      const result = await addPatternsFromTxt(txtFile, uploadPatternType);
      setUploadResult(result);
      const typeLabel = patternTypes.find(t => t.value === uploadPatternType)?.label || uploadPatternType;
      setSnackbar({ open: true, message: `${result.success} ${typeLabel} pattern eklendi, ${result.failed} hata.`, severity: result.failed === 0 ? 'success' : 'error' });
      setTxtFile(null);
      fetchPatterns();
    } catch (e: any) {
      setUploadResult({ success: 0, failed: 0, errors: [e.message || 'Bilinmeyen hata'] });
      setSnackbar({ open: true, message: 'Yükleme başarısız.', severity: 'error' });
    } finally {
      setUploading(false);
    }
  };

  // Modal aç/kapat
  const openAddModal = () => { setOpenAdd(true); reset(defaultFormValues); };
  const openEditModal = (pattern: Pattern) => { setEditPattern(pattern); setOpenEdit(true); resetEdit(pattern); };
  const closeModals = () => { setOpenAdd(false); setOpenEdit(false); setEditPattern(null); reset(defaultFormValues); resetEdit(defaultFormValues); };

  return (
    <Box p={3}>
      <Typography variant="h4" mb={2}>Pattern Yönetimi</Typography>
      <Stack direction="row" spacing={2} mb={2} alignItems="center">
        <Button variant="contained" startIcon={<Add />} onClick={openAddModal} aria-label="Yeni Pattern Ekle">Yeni Pattern Ekle</Button>
        <Button variant="outlined" startIcon={<UploadFile />} onClick={() => setOpenUpload(true)} aria-label="Pattern Yükle">Pattern Yükle</Button>
        <Select
          value={filter}
          onChange={e => setFilter(e.target.value as PatternType | '')}
          size="small"
          sx={{ minWidth: 120 }}
          aria-label="Filtrele"
        >
          <MenuItem value="">Tümü</MenuItem>
          {patternTypes.map(t => <MenuItem key={t.value} value={t.value}>{t.label}</MenuItem>)}
        </Select>
        <TextField
          size="small"
          placeholder="Ara..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Search />
              </InputAdornment>
            )
          }}
          aria-label="Ara"
        />
        <Select value={pageSize} onChange={e => setPageSize(Number(e.target.value))} size="small" sx={{ minWidth: 80 }} aria-label="Sayfa Boyutu">
          {[10, 20, 50, 100].map(size => <MenuItem key={size} value={size}>{size}/sayfa</MenuItem>)}
        </Select>
      </Stack>
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Pattern</TableCell>
              <TableCell>Tipi</TableCell>
              <TableCell>Açıklama</TableCell>
              <TableCell align="right">İşlemler</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow><TableCell colSpan={4} align="center"><CircularProgress /></TableCell></TableRow>
            ) : patterns.length === 0 ? (
              <TableRow><TableCell colSpan={4} align="center">Hiç kayıt yok.</TableCell></TableRow>
            ) : patterns.map((pattern) => (
              <TableRow key={pattern.id}>
                <TableCell><Typography fontFamily="monospace">{pattern.pattern}</Typography></TableCell>
                <TableCell>
                  <Chip
                    label={patternTypes.find(t => t.value === pattern.type)?.label || pattern.type}
                    color={patternTypes.find(t => t.value === pattern.type)?.color as any}
                    size="small"
                  />
                </TableCell>
                <TableCell>{pattern.description}</TableCell>
                <TableCell align="right">
                  <Tooltip title="Düzenle"><IconButton onClick={() => openEditModal(pattern)} aria-label="Düzenle"><Edit /></IconButton></Tooltip>
                  <Tooltip title="Sil"><IconButton color="error" onClick={() => setOpenDelete({ open: true, id: pattern.id })} aria-label="Sil"><Delete /></IconButton></Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      <Box display="flex" justifyContent="space-between" alignItems="center" mt={2}>
        <Typography variant="body2">Toplam: {total}</Typography>
        <Pagination
          count={Math.ceil(total / pageSize)}
          page={page}
          onChange={(_e, val) => setPage(val)}
          color="primary"
          shape="rounded"
          showFirstButton
          showLastButton
          aria-label="Sayfalama"
        />
      </Box>
      {/* Pattern Ekle Modal */}
      <Dialog open={openAdd} onClose={closeModals} maxWidth="xs" fullWidth aria-label="Yeni Pattern Modalı">
        <DialogTitle>Yeni Pattern Ekle</DialogTitle>
        <form onSubmit={handleSubmit(onAdd)}>
          <DialogContent>
            <Controller
              name="pattern"
              control={control}
              rules={{ required: 'Pattern zorunlu' }}
              render={({ field, fieldState }: { field: any; fieldState: any }) => (
                <TextField {...field} label="Pattern" fullWidth margin="normal" error={!!fieldState.error} helperText={fieldState.error?.message} aria-label="Pattern" />
              )}
            />
            <Controller
              name="type"
              control={control}
              render={({ field }: { field: any }) => (
                <Select {...field} label="Tip" fullWidth sx={{ mt: 2 }} aria-label="Tip">
                  {patternTypes.map(t => <MenuItem key={t.value} value={t.value}>{t.label}</MenuItem>)}
                </Select>
              )}
            />
            <Controller
              name="description"
              control={control}
              render={({ field }: { field: any }) => (
                <TextField {...field} label="Açıklama" fullWidth margin="normal" aria-label="Açıklama" />
              )}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={closeModals}>İptal</Button>
            <Button type="submit" variant="contained">Ekle</Button>
          </DialogActions>
        </form>
      </Dialog>
      {/* Pattern Düzenle Modal */}
      <Dialog open={openEdit} onClose={closeModals} maxWidth="xs" fullWidth aria-label="Pattern Düzenle Modalı">
        <DialogTitle>Pattern Düzenle</DialogTitle>
        <form onSubmit={handleEditSubmit(onEdit)}>
          <DialogContent>
            <Controller
              name="pattern"
              control={editControl}
              rules={{ required: 'Pattern zorunlu' }}
              render={({ field, fieldState }: { field: any; fieldState: any }) => (
                <TextField {...field} label="Pattern" fullWidth margin="normal" error={!!fieldState.error} helperText={fieldState.error?.message} aria-label="Pattern" />
              )}
            />
            <Controller
              name="type"
              control={editControl}
              render={({ field }: { field: any }) => (
                <Select {...field} label="Tip" fullWidth sx={{ mt: 2 }} aria-label="Tip">
                  {patternTypes.map(t => <MenuItem key={t.value} value={t.value}>{t.label}</MenuItem>)}
                </Select>
              )}
            />
            <Controller
              name="description"
              control={editControl}
              render={({ field }: { field: any }) => (
                <TextField {...field} label="Açıklama" fullWidth margin="normal" aria-label="Açıklama" />
              )}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={closeModals}>İptal</Button>
            <Button type="submit" variant="contained">Kaydet</Button>
          </DialogActions>
        </form>
      </Dialog>
      {/* Dosya ile Yükle Modal */}
      <Dialog open={openUpload} onClose={() => {
        setOpenUpload(false);
        setTxtFile(null);
        setUploadPatternType(PatternType.CUSTOM);
        setUploadResult(null);
      }} maxWidth="xs" fullWidth aria-label="Pattern Dosyası Yükle Modalı">
        <DialogTitle>Pattern Dosyası Yükle</DialogTitle>
        <DialogContent>
          <Box
            {...getRootProps()}
            sx={{
              border: '2px dashed #90caf9',
              borderRadius: 2,
              p: 3,
              textAlign: 'center',
              cursor: 'pointer',
              bgcolor: isDragActive ? '#e3f2fd' : '#fafafa'
            }}
            aria-label="Dosya Yükleme Alanı"
          >
            <input {...getInputProps()} />
            <UploadFile sx={{ fontSize: 40, color: '#90caf9' }} />
            <Typography mt={1}>
              {isDragActive ? 'Bırakabilirsin' : 'Dosyanı buraya sürükle veya tıkla'}
            </Typography>
            <Typography variant="body2" color="text.secondary" mt={1}>
              Sadece .txt dosyası. Her satırda bir pattern, virgül ile tip ve açıklama ekleyebilirsin.<br />
              <a href="/example-patterns.txt" download>Örnek dosya indir</a>
            </Typography>
          </Box>
          {txtFile && <Typography mt={2}>Seçilen dosya: {txtFile.name}</Typography>}
          <Box mt={2}>
            <Typography variant="subtitle2" gutterBottom>Pattern Tipi:</Typography>
            <Select
              value={uploadPatternType}
              onChange={(e) => setUploadPatternType(e.target.value as PatternType)}
              fullWidth
              size="small"
              aria-label="Pattern Tipi Seç"
            >
              {patternTypes.map(t => (
                <MenuItem key={t.value} value={t.value}>
                  <Chip
                    label={t.label}
                    color={t.color as any}
                    size="small"
                    sx={{ mr: 1 }}
                  />
                  {t.label}
                </MenuItem>
              ))}
            </Select>
          </Box>
          {uploading && <Typography mt={2}>Yükleniyor...</Typography>}
          {uploadResult && (
            <Box mt={2}>
              <Alert severity={uploadResult.failed === 0 ? 'success' : 'warning'}>
                {uploadResult.success} pattern eklendi, {uploadResult.failed} hata.<br />
                {uploadResult.errors.length > 0 && (
                  <ul style={{ margin: 0, paddingLeft: 20 }}>
                    {uploadResult.errors.map((err, i) => <li key={i}>{err}</li>)}
                  </ul>
                )}
              </Alert>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            setOpenUpload(false);
            setTxtFile(null);
            setUploadPatternType(PatternType.CUSTOM);
            setUploadResult(null);
          }}>Kapat</Button>
          <Button onClick={handleTxtUpload} variant="contained" disabled={!txtFile || uploading}>Yükle</Button>
        </DialogActions>
      </Dialog>
      {/* Silme Onay Modalı */}
      <Dialog open={openDelete.open} onClose={() => setOpenDelete({ open: false, id: null })} maxWidth="xs" fullWidth aria-label="Silme Onay Modalı">
        <DialogTitle>Pattern Sil</DialogTitle>
        <DialogContent>
          <Typography>Bu pattern'ı silmek istediğinize emin misiniz?</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDelete({ open: false, id: null })}>İptal</Button>
          <Button onClick={onDelete} color="error" variant="contained">Sil</Button>
        </DialogActions>
      </Dialog>
      {/* Snackbar */}
      <Snackbar open={snackbar.open} autoHideDuration={4000} onClose={() => setSnackbar(s => ({ ...s, open: false }))}>
        <Alert severity={snackbar.severity} onClose={() => setSnackbar(s => ({ ...s, open: false }))}>
          {snackbar.message}
        </Alert>
      </Snackbar>
      {/* Hata Alerti */}
      {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
    </Box>
  );
};

export default PatternManagement; 