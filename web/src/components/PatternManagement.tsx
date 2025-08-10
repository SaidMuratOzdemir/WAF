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

// Base types supported by backend
const patternTypes = [
  { value: PatternType.XSS, label: 'XSS', color: 'error' },
  { value: PatternType.SQL, label: 'SQL', color: 'primary' },
  { value: PatternType.CUSTOM, label: 'CUSTOM', color: 'default' },
];

// Extended UI-only types for filter and upload selection
const extendedPatternTypes: Array<{
  value: string;
  label: string;
  color: 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning';
  backendType: PatternType;
  uiOnly?: boolean;
}> = [
  // Backend-backed
  { value: PatternType.XSS, label: 'XSS', color: 'error', backendType: PatternType.XSS },
  { value: PatternType.SQL, label: 'SQL', color: 'primary', backendType: PatternType.SQL },
  { value: PatternType.CUSTOM, label: 'CUSTOM', color: 'default', backendType: PatternType.CUSTOM },
  // UI-only categories (mapped to CUSTOM for backend)
  { value: 'RCE', label: 'RCE', color: 'warning', backendType: PatternType.CUSTOM, uiOnly: true },
  { value: 'LFI', label: 'LFI', color: 'warning', backendType: PatternType.CUSTOM, uiOnly: true },
  { value: 'SSRF', label: 'SSRF', color: 'warning', backendType: PatternType.CUSTOM, uiOnly: true },
  { value: 'OpenRedirect', label: 'Open Redirect', color: 'info', backendType: PatternType.CUSTOM, uiOnly: true },
  { value: 'PathTraversal', label: 'Path Traversal', color: 'info', backendType: PatternType.CUSTOM, uiOnly: true },
  { value: 'XXE', label: 'XXE', color: 'secondary', backendType: PatternType.CUSTOM, uiOnly: true },
  { value: 'CSRF', label: 'CSRF', color: 'secondary', backendType: PatternType.CUSTOM, uiOnly: true },
];

const defaultFormValues = { pattern: '', type: PatternType.CUSTOM, description: '' };

type PatternFormData = PatternCreate;

const PatternManagement: React.FC = () => {
  const [patterns, setPatterns] = useState<Pattern[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [filter, setFilter] = useState<string | ''>('');
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
  const [uploadPatternType, setUploadPatternType] = useState<string>(PatternType.CUSTOM);

  // react-hook-form
  const { control, handleSubmit, reset } = useForm<PatternFormData>({ defaultValues: defaultFormValues });
  const { control: editControl, handleSubmit: handleEditSubmit, reset: resetEdit } = useForm<PatternFormData>({ defaultValues: defaultFormValues });

  // File upload
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop: (files: File[]) => setTxtFile(files[0]),
    accept: { 'text/plain': ['.txt'] },
    multiple: false
  });

  // Debounced search
  const debouncedSetSearch = useMemo(() => debounce((val: string) => setSearchDebounced(val), 400), []);
  useEffect(() => { debouncedSetSearch(search); }, [search, debouncedSetSearch]);

  // Fetch patterns
  const fetchPatterns = async (pageArg = page, pageSizeArg = pageSize, filterArg = filter, searchArg = searchDebounced) => {
    setLoading(true);
    try {
      // Only pass filter to backend if it's one of the supported enum values; UI-only types are handled visually only
      const enumValues = Object.values(PatternType) as string[];
      const backendFilter = (filterArg && enumValues.includes(filterArg as string)) ? (filterArg as PatternType) : undefined;
      const res = await getPatterns(pageArg, pageSizeArg, backendFilter, searchArg || undefined);
      setPatterns(res.items);
      setTotal(res.total);
      setError(null);
    } catch (e: any) {
      setError(e.message || 'Failed to fetch data.');
      setPatterns([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchPatterns(1, pageSize, filter, searchDebounced); setPage(1); }, [filter, pageSize, searchDebounced]);
  useEffect(() => { fetchPatterns(page, pageSize, filter, searchDebounced); }, [page]);

  // Add pattern
  const onAdd = async (data: PatternFormData) => {
    try {
      // Type should come from enum
      await addPattern({ ...data, type: data.type as PatternType });
      setSnackbar({ open: true, message: 'Pattern added successfully.', severity: 'success' });
      setOpenAdd(false);
      reset(defaultFormValues);
      fetchPatterns();
    } catch (e: any) {
      setSnackbar({ open: true, message: e.message || JSON.stringify(e), severity: 'error' });
    }
  };

  // Update pattern
  const onEdit = async (data: PatternFormData) => {
    if (!editPattern) return;
    try {
      await updatePattern(editPattern.id, { ...data, type: data.type as PatternType });
      setSnackbar({ open: true, message: 'Pattern updated.', severity: 'success' });
      setOpenEdit(false);
      setEditPattern(null);
      fetchPatterns();
    } catch (e: any) {
      setSnackbar({ open: true, message: e.message || JSON.stringify(e), severity: 'error' });
    }
  };

  // Delete pattern
  const onDelete = async () => {
    if (!openDelete.id) return;
    try {
      await deletePattern(openDelete.id);
      setSnackbar({ open: true, message: 'Pattern deleted.', severity: 'success' });
      setOpenDelete({ open: false, id: null });
      fetchPatterns();
    } catch (e: any) {
      setSnackbar({ open: true, message: e.message || 'Failed to delete pattern.', severity: 'error' });
    }
  };

  // Upload via file
  const handleTxtUpload = async () => {
    if (!txtFile) return;
    setUploading(true);
    try {
      const backendType = (extendedPatternTypes.find(t => t.value === uploadPatternType)?.backendType) ?? PatternType.CUSTOM;
      const result = await addPatternsFromTxt(txtFile, backendType);
      setUploadResult(result);
      const typeLabel = (extendedPatternTypes.find(t => t.value === uploadPatternType)?.label) || uploadPatternType;
      setSnackbar({ open: true, message: `${result.success} ${typeLabel} patterns added, ${result.failed} errors.`, severity: result.failed === 0 ? 'success' : 'error' });
      setTxtFile(null);
      fetchPatterns();
    } catch (e: any) {
      setUploadResult({ success: 0, failed: 0, errors: [e.message || 'Unknown error'] });
      setSnackbar({ open: true, message: 'Upload failed.', severity: 'error' });
    } finally {
      setUploading(false);
    }
  };

  // Open/close modals
  const openAddModal = () => { setOpenAdd(true); reset(defaultFormValues); };
  const openEditModal = (pattern: Pattern) => { setEditPattern(pattern); setOpenEdit(true); resetEdit(pattern); };
  const closeModals = () => { setOpenAdd(false); setOpenEdit(false); setEditPattern(null); reset(defaultFormValues); resetEdit(defaultFormValues); };

  return (
    <Box p={3}>
      <Typography variant="h4" mb={2}>Pattern Management</Typography>
      <Stack direction="row" spacing={2} mb={2} alignItems="center">
        <Button variant="contained" startIcon={<Add />} onClick={openAddModal} aria-label="Add New Pattern">Add New Pattern</Button>
        <Button variant="outlined" startIcon={<UploadFile />} onClick={() => setOpenUpload(true)} aria-label="Upload Patterns">Upload Patterns</Button>
        <Select
          value={filter}
          onChange={e => setFilter(e.target.value as string)}
          size="small"
          sx={{ minWidth: 120 }}
          aria-label="Filter"
        >
          <MenuItem value="">All</MenuItem>
          {extendedPatternTypes.map(t => <MenuItem key={t.value} value={t.value}>{t.label}</MenuItem>)}
        </Select>
        <TextField
          size="small"
          placeholder="Search..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Search />
              </InputAdornment>
            )
          }}
          aria-label="Search"
        />
        <Select value={pageSize} onChange={e => setPageSize(Number(e.target.value))} size="small" sx={{ minWidth: 80 }} aria-label="Page Size">
          {[10, 20, 50, 100].map(size => <MenuItem key={size} value={size}>{size}/page</MenuItem>)}
        </Select>
      </Stack>
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Pattern</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Description</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow><TableCell colSpan={4} align="center"><CircularProgress /></TableCell></TableRow>
            ) : patterns.length === 0 ? (
              <TableRow><TableCell colSpan={4} align="center">No records found.</TableCell></TableRow>
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
                  <Tooltip title="Edit"><IconButton onClick={() => openEditModal(pattern)} aria-label="Edit"><Edit /></IconButton></Tooltip>
                  <Tooltip title="Delete"><IconButton color="error" onClick={() => setOpenDelete({ open: true, id: pattern.id })} aria-label="Delete"><Delete /></IconButton></Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      <Box display="flex" justifyContent="space-between" alignItems="center" mt={2}>
        <Typography variant="body2">Total: {total}</Typography>
        <Pagination
          count={Math.ceil(total / pageSize)}
          page={page}
          onChange={(_e, val) => setPage(val)}
          color="primary"
          shape="rounded"
          showFirstButton
          showLastButton
          aria-label="Pagination"
        />
      </Box>
      {/* Add Pattern Modal */}
      <Dialog open={openAdd} onClose={closeModals} maxWidth="xs" fullWidth aria-label="Add New Pattern Modal">
        <DialogTitle>Add New Pattern</DialogTitle>
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
                <Select {...field} label="Type" fullWidth sx={{ mt: 2 }} aria-label="Type">
                  {patternTypes.map(t => <MenuItem key={t.value} value={t.value}>{t.label}</MenuItem>)}
                </Select>
              )}
            />
            <Controller
              name="description"
              control={control}
              render={({ field }: { field: any }) => (
                <TextField {...field} label="Description" fullWidth margin="normal" aria-label="Description" />
              )}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={closeModals}>Cancel</Button>
            <Button type="submit" variant="contained">Add</Button>
          </DialogActions>
        </form>
      </Dialog>
      {/* Edit Pattern Modal */}
      <Dialog open={openEdit} onClose={closeModals} maxWidth="xs" fullWidth aria-label="Edit Pattern Modal">
        <DialogTitle>Edit Pattern</DialogTitle>
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
                <Select {...field} label="Type" fullWidth sx={{ mt: 2 }} aria-label="Type">
                  {patternTypes.map(t => <MenuItem key={t.value} value={t.value}>{t.label}</MenuItem>)}
                </Select>
              )}
            />
            <Controller
              name="description"
              control={editControl}
              render={({ field }: { field: any }) => (
                <TextField {...field} label="Description" fullWidth margin="normal" aria-label="Description" />
              )}
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={closeModals}>Cancel</Button>
            <Button type="submit" variant="contained">Save</Button>
          </DialogActions>
        </form>
      </Dialog>
      {/* Upload File Modal */}
      <Dialog open={openUpload} onClose={() => {
        setOpenUpload(false);
        setTxtFile(null);
        setUploadPatternType(PatternType.CUSTOM);
        setUploadResult(null);
      }} maxWidth="xs" fullWidth aria-label="Upload Pattern File Modal">
        <DialogTitle>Upload Pattern File</DialogTitle>
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
            aria-label="File Upload Area"
          >
            <input {...getInputProps()} />
            <UploadFile sx={{ fontSize: 40, color: '#90caf9' }} />
            <Typography mt={1}>
              {isDragActive ? 'Drop here' : 'Drag and drop your file here, or click to select'}
            </Typography>
            <Typography variant="body2" color="text.secondary" mt={1}>
              Only .txt files. Each line: pattern, comma, type and optional description.<br />
              <a href="/example-patterns.txt" download>Download example file</a>
            </Typography>
          </Box>
          {txtFile && <Typography mt={2}>Selected file: {txtFile.name}</Typography>}
          <Box mt={2}>
            <Typography variant="subtitle2" gutterBottom>Pattern Type:</Typography>
            <Select
              value={uploadPatternType}
              onChange={(e) => setUploadPatternType(e.target.value as any)}
              fullWidth
              size="small"
              aria-label="Select Pattern Type"
            >
              {extendedPatternTypes.map(t => (
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
          {uploading && <Typography mt={2}>Uploading...</Typography>}
          {uploadResult && (
            <Box mt={2}>
              <Alert severity={uploadResult.failed === 0 ? 'success' : 'warning'}>
                {uploadResult.success} patterns added, {uploadResult.failed} errors.<br />
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
          }}>Close</Button>
          <Button onClick={handleTxtUpload} variant="contained" disabled={!txtFile || uploading}>Upload</Button>
        </DialogActions>
      </Dialog>
      {/* Delete Confirmation Modal */}
      <Dialog open={openDelete.open} onClose={() => setOpenDelete({ open: false, id: null })} maxWidth="xs" fullWidth aria-label="Delete Confirmation Modal">
        <DialogTitle>Delete Pattern</DialogTitle>
        <DialogContent>
          <Typography>Are you sure you want to delete this pattern?</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDelete({ open: false, id: null })}>Cancel</Button>
          <Button onClick={onDelete} color="error" variant="contained">Delete</Button>
        </DialogActions>
      </Dialog>
      {/* Snackbar */}
      <Snackbar open={snackbar.open} autoHideDuration={4000} onClose={() => setSnackbar(s => ({ ...s, open: false }))}>
        <Alert severity={snackbar.severity} onClose={() => setSnackbar(s => ({ ...s, open: false }))}>
          {snackbar.message}
        </Alert>
      </Snackbar>
      {/* Error Alert */}
      {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
    </Box>
  );
};

export default PatternManagement; 