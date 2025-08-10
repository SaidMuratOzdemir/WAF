import { useRef, useCallback, lazy, Suspense } from 'react';
const IPManagement = lazy(() => import('./components/IPManagement'));
const LogViewer = lazy(() => import('./components/LogViewer'));
import { Container, Box } from '@mui/material';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { SiteList, SiteListRef } from './components/SiteList';
import { SiteForm } from './components/SiteForm';
import { Login } from './components/Login';
import VirusTotalStats from './components/VirusTotalStats';
import { AuthProvider, useAuth } from './context/AuthContext';
import PatternManagement from './components/PatternManagement';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { checkAuth } = useAuth();
  
  if (!checkAuth()) {
    return <Navigate to="/login" />;
  }

  return <>{children}</>;
}

function SitesPage() {
  const siteListRef = useRef<SiteListRef>(null);

  const handleSiteAdded = useCallback(() => {
    console.log('handleSiteAdded called, forcing refresh');
    // Call refresh method on SiteList
    if (siteListRef.current) {
      siteListRef.current.refresh();
    }
  }, []);

  return (
    <Container>
      <Box sx={{ mb: 4 }}>
        <VirusTotalStats />
      </Box>
      <SiteForm onSiteAdded={handleSiteAdded} />
      <Box sx={{ mt: 4 }}>
        <SiteList ref={siteListRef} />
      </Box>
    </Container>
  );
}

function App() {
  return (
    <Router>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/sites"
            element={
              <ProtectedRoute>
                <SitesPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/ip-management"
            element={
              <ProtectedRoute>
                <Suspense fallback={<div>Loading...</div>}>
                  <IPManagement />
                </Suspense>
              </ProtectedRoute>
            }
          />
          <Route
            path="/patterns"
            element={
              <ProtectedRoute>
                <Suspense fallback={<div>Loading...</div>}>
                  <PatternManagement />
                </Suspense>
              </ProtectedRoute>
            }
          />
          <Route
            path="/logs"
            element={
              <ProtectedRoute>
                <Suspense fallback={<div>Loading...</div>}>
                  <LogViewer />
                </Suspense>
              </ProtectedRoute>
            }
          />
          <Route path="/" element={<Navigate to="/sites" />} />
        </Routes>
      </AuthProvider>
    </Router>
  );
}

export default App;
