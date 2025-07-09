import { useRef, useCallback } from 'react';
import { Container, AppBar, Toolbar, Typography, Box, Button } from '@mui/material';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { SiteList, SiteListRef } from './components/SiteList';
import { SiteForm } from './components/SiteForm';
import { Login } from './components/Login';
import VirusTotalStats from './components/VirusTotalStats';
import { AuthProvider, useAuth } from './context/AuthContext';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { checkAuth } = useAuth();
  
  if (!checkAuth()) {
    return <Navigate to="/login" />;
  }

  return <>{children}</>;
}

function Dashboard() {
  const siteListRef = useRef<SiteListRef>(null);
  const { logout } = useAuth();

  const handleSiteAdded = useCallback(() => {
    console.log('handleSiteAdded called, forcing refresh');
    // Call refresh method on SiteList
    if (siteListRef.current) {
      siteListRef.current.refresh();
    }
  }, []);

  return (
    <Box sx={{ flexGrow: 1 }}>
      <AppBar position="static" sx={{ mb: 4 }}>
        <Toolbar>
          <Typography variant="h6" component="h1" sx={{ flexGrow: 1 }}>
            WAF Management Console
          </Typography>
          <Button color="inherit" onClick={logout}>
            Logout
          </Button>
        </Toolbar>
      </AppBar>
      
      <Container>
        <Box sx={{ mb: 4 }}>
          <VirusTotalStats />
        </Box>
        <SiteForm onSiteAdded={handleSiteAdded} />
        <Box sx={{ mt: 4 }}>
          <SiteList ref={siteListRef} />
        </Box>
      </Container>
    </Box>
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
                <Dashboard />
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
