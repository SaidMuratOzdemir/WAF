import { useEffect, useState, forwardRef, useImperativeHandle } from 'react';
import {
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    TablePagination,
    TableSortLabel,
    Paper,
    IconButton,
    Typography,
    Box,
    Alert,
    AlertTitle,
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    Snackbar,
    Skeleton,
    Tooltip,
} from '@mui/material';
import { Delete as DeleteIcon, Edit as EditIcon, Circle as CircleIcon } from '@mui/icons-material';
import type { Site } from '../types/Site';
import { fetchSites, deleteSite } from '../api/sites';
import EditSiteModal from './EditSiteModal';

type Order = 'asc' | 'desc';
type OrderBy = keyof Omit<Site, 'id' | 'xss_enabled' | 'sql_enabled'>;

function descendingComparator<T>(a: T, b: T, orderBy: keyof T) {
    if (b[orderBy] < a[orderBy]) return -1;
    if (b[orderBy] > a[orderBy]) return 1;
    return 0;
}

function getComparator<T>(
    order: Order,
    orderBy: keyof T,
): (a: T, b: T) => number {
    return order === 'desc'
        ? (a, b) => descendingComparator(a, b, orderBy)
        : (a, b) => -descendingComparator(a, b, orderBy);
}

interface SiteListProps {
    onRefreshRequest?: () => void;
}

export interface SiteListRef {
    refresh: () => void;
}

export const SiteList = forwardRef<SiteListRef, SiteListProps>(
    ({ onRefreshRequest }, ref) => {
    const [sites, setSites] = useState<Site[]>([]);
    const [error, setError] = useState<string>('');
    const [loading, setLoading] = useState(true);
    const [siteToDelete, setSiteToDelete] = useState<Site | null>(null);
    const [siteToEdit, setSiteToEdit] = useState<Site | null>(null);
    const [openDialog, setOpenDialog] = useState(false);
    const [editModalOpen, setEditModalOpen] = useState(false);
    const [order, setOrder] = useState<Order>('asc');
    const [orderBy, setOrderBy] = useState<OrderBy>('port');
    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(5);
    const [snackbar, setSnackbar] = useState<{
        open: boolean;
        message: string;
        severity: 'success' | 'error';
    }>({
        open: false,
        message: '',
        severity: 'success'
    });

    const loadSites = async () => {
        try {
            console.log('loadSites called, setting loading to true');
            setLoading(true);
            const data = await fetchSites();
            console.log('fetchSites returned:', data);
            setSites(data);
        } catch (e) {
            console.error('Error in loadSites:', e);
            setError(e instanceof Error ? e.message : 'Failed to load sites');
        } finally {
            setLoading(false);
            console.log('loadSites finished, setting loading to false');
        }
    };

    const handleRequestSort = (property: OrderBy) => {
        const isAsc = orderBy === property && order === 'asc';
        setOrder(isAsc ? 'desc' : 'asc');
        setOrderBy(property);
    };

    const handleChangePage = (_event: unknown, newPage: number) => {
        setPage(newPage);
    };

    const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
        setRowsPerPage(parseInt(event.target.value, 10));
        setPage(0);
    };

    const handleDelete = async (site: Site) => {
        try {
            await deleteSite(site.id);
            setSites(sites.filter(s => s.id !== site.id));
            setSnackbar({
                open: true,
                message: `Site "${site.name}" (${site.host}:${site.port}) has been removed.`,
                severity: 'success'
            });
        } catch (e) {
            setSnackbar({
                open: true,
                message: e instanceof Error ? e.message : 'Failed to delete site',
                severity: 'error'
            });
        }
        setOpenDialog(false);
    };

    const handleCloseSnackbar = () => {
        setSnackbar({ ...snackbar, open: false });
    };

    const openDeleteConfirm = (site: Site) => {
        setSiteToDelete(site);
        setOpenDialog(true);
    };

    const openEditModal = (site: Site) => {
        setSiteToEdit(site);
        setEditModalOpen(true);
    };

    const handleEditSuccess = () => {
        setSnackbar({
            open: true,
            message: 'Site successfully updated!',
            severity: 'success'
        });
        loadSites(); // Refresh the list
    };

    useImperativeHandle(ref, () => ({
        refresh: loadSites
    }));

    useEffect(() => {
        console.log('SiteList mounted, loading sites');
        loadSites();
    }, []);

    if (error) {
        return (
            <Alert severity="error">
                <AlertTitle>Error</AlertTitle>
                {error}
            </Alert>
        );
    }

    const sortedSites = loading ? [] : [...sites].sort(getComparator(order, orderBy));
    const paginatedSites = sortedSites.slice(
        page * rowsPerPage,
        page * rowsPerPage + rowsPerPage
    );

    const LoadingRows = () => (
        <>
            {[...Array(rowsPerPage)].map((_, index) => (
                <TableRow key={index}>
                    {[...Array(8)].map((_, cellIndex) => (
                        <TableCell key={cellIndex}>
                            {cellIndex === 0 ? (
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <Skeleton variant="circular" width={12} height={12} />
                                    <Skeleton animation="wave" width={40} />
                                </Box>
                            ) : (
                                <Skeleton animation="wave" />
                            )}
                        </TableCell>
                    ))}
                </TableRow>
            ))}
        </>
    );

    return (
        <Box sx={{ width: '100%', p: 3 }}>
            <Typography variant="h4" sx={{ mb: 3 }}>Protected Sites</Typography>
            
            <TableContainer component={Paper}>
                <Table>
                    <TableHead>
                        <TableRow>
                            {[
                                { id: 'port' as OrderBy, label: 'Port' },
                                { id: 'host' as OrderBy, label: 'Host' },
                                { id: 'name' as OrderBy, label: 'Name' },
                                { id: 'frontend_url' as OrderBy, label: 'Frontend URL' },
                                { id: 'backend_url' as OrderBy, label: 'Backend URL' },
                                { id: 'xss_enabled', label: 'XSS Protection', sortable: false },
                                { id: 'sql_enabled', label: 'SQL Protection', sortable: false },
                                { id: 'actions', label: 'Actions', sortable: false }
                            ].map((column) => (
                                <TableCell key={column.id}>
                                    {column.sortable === false ? (
                                        column.label
                                    ) : (
                                        <TableSortLabel
                                            active={orderBy === column.id}
                                            direction={orderBy === column.id ? order : 'asc'}
                                            onClick={() => handleRequestSort(column.id as OrderBy)}
                                        >
                                            {column.label}
                                        </TableSortLabel>
                                    )}
                                </TableCell>
                            ))}
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {loading ? (
                            <LoadingRows />
                        ) : paginatedSites.length === 0 ? (
                            <TableRow>
                                <TableCell colSpan={8} align="center">
                                    <Typography variant="body1" sx={{ py: 2 }}>
                                        No protected sites found
                                    </Typography>
                                </TableCell>
                            </TableRow>
                        ) : (
                            paginatedSites.map(site => (
                                <TableRow key={site.id}>
                                    <TableCell>
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                            <Tooltip 
                                                title={
                                                    site.health_status === 'healthy' ? 'Site is healthy and responding' :
                                                    site.health_status === 'unhealthy' ? 'Site is down or not responding' :
                                                    site.health_status ? 'Health status unknown' : 'No health data available'
                                                }
                                                arrow
                                            >
                                                <CircleIcon 
                                                    sx={{ 
                                                        fontSize: 12,
                                                        color: site.health_status === 'healthy' ? 'success.main' : 
                                                               site.health_status === 'unhealthy' ? 'error.main' : 
                                                               site.health_status ? 'warning.main' : 'grey.500'
                                                    }} 
                                                />
                                            </Tooltip>
                                            {site.port}
                                        </Box>
                                    </TableCell>
                                    <TableCell>{site.host}</TableCell>
                                    <TableCell>{site.name}</TableCell>
                                    <TableCell>{site.frontend_url}</TableCell>
                                    <TableCell>{site.backend_url}</TableCell>
                                    <TableCell>{site.xss_enabled ? 'Yes' : 'No'}</TableCell>
                                    <TableCell>{site.sql_enabled ? 'Yes' : 'No'}</TableCell>
                                    <TableCell>
                                        <IconButton
                                            aria-label="Edit site"
                                            color="primary"
                                            onClick={() => openEditModal(site)}
                                            sx={{ mr: 1 }}
                                        >
                                            <EditIcon />
                                        </IconButton>
                                        <IconButton
                                            aria-label="Delete site"
                                            color="error"
                                            onClick={() => openDeleteConfirm(site)}
                                        >
                                            <DeleteIcon />
                                        </IconButton>
                                    </TableCell>
                                </TableRow>
                            ))
                        )}
                    </TableBody>
                </Table>
                <TablePagination
                    rowsPerPageOptions={[5, 10, 25]}
                    component="div"
                    count={sites.length}
                    rowsPerPage={rowsPerPage}
                    page={page}
                    onPageChange={handleChangePage}
                    onRowsPerPageChange={handleChangeRowsPerPage}
                />
            </TableContainer>

            <Dialog
                open={openDialog}
                onClose={() => setOpenDialog(false)}
            >
                <DialogTitle>
                    Delete Site
                </DialogTitle>
                <DialogContent>
                    <DialogContentText>
                        Are you sure you want to delete the site "{siteToDelete?.name}" 
                        ({siteToDelete?.host}:{siteToDelete?.port})? This action cannot be undone.
                    </DialogContentText>
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setOpenDialog(false)}>
                        Cancel
                    </Button>
                    <Button 
                        color="error" 
                        onClick={() => siteToDelete && handleDelete(siteToDelete)}
                        autoFocus
                    >
                        Delete
                    </Button>
                </DialogActions>
            </Dialog>

            <EditSiteModal
                open={editModalOpen}
                site={siteToEdit}
                onClose={() => setEditModalOpen(false)}
                onSuccess={handleEditSuccess}
            />

            <Snackbar 
                open={snackbar.open} 
                autoHideDuration={5000} 
                onClose={handleCloseSnackbar}
            >
                <Alert 
                    onClose={handleCloseSnackbar} 
                    severity={snackbar.severity}
                >
                    {snackbar.message}
                </Alert>
            </Snackbar>
        </Box>
    );
});

SiteList.displayName = 'SiteList';
