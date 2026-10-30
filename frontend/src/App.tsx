import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { CaseProvider, useCase } from "./auth/CaseContext";
import { Layout } from "./components/Layout";
import { ToastProvider } from "./components/Toast";
import { Empty, Loading } from "./components/ui";
import BrowserPage from "./pages/Browser";
import CasesPage from "./pages/Cases";
import CustodyPage from "./pages/Custody";
import EventsPage from "./pages/Events";
import EvidencePage from "./pages/Evidence";
import IocsPage from "./pages/Iocs";
import LoginPage from "./pages/Login";
import MalwarePage from "./pages/Malware";
import OverviewPage from "./pages/Overview";
import ReportsPage from "./pages/Reports";
import SettingsPage from "./pages/Settings";
import TimelinePage from "./pages/Timeline";

/** Pages that operate on the selected case render a hint when no case exists yet. */
function NeedsCase({ children }: { children: JSX.Element }) {
  const { caseId, loading, error } = useCase();
  if (loading) return <Loading label="Loading cases…" />;
  if (error) return <Empty>Could not load cases: {error.message}</Empty>;
  if (!caseId) return <Empty>No investigation exists yet. Create one under Investigations.</Empty>;
  return children;
}

function Shell() {
  const { user, ready } = useAuth();
  if (!ready) {
    return (
      <div className="flex h-screen items-center justify-center bg-ink-950">
        <Loading label="Checking session…" />
      </div>
    );
  }
  if (!user) {
    return (
      <Routes>
        <Route path="*" element={<LoginPage />} />
      </Routes>
    );
  }
  return (
    <CaseProvider>
      <Layout>
        <Routes>
          <Route path="/" element={<NeedsCase><OverviewPage /></NeedsCase>} />
          <Route path="/cases" element={<CasesPage />} />
          <Route path="/evidence" element={<NeedsCase><EvidencePage /></NeedsCase>} />
          <Route path="/malware" element={<NeedsCase><MalwarePage /></NeedsCase>} />
          <Route path="/events" element={<NeedsCase><EventsPage /></NeedsCase>} />
          <Route path="/browser" element={<NeedsCase><BrowserPage /></NeedsCase>} />
          <Route path="/timeline" element={<NeedsCase><TimelinePage /></NeedsCase>} />
          <Route path="/iocs" element={<NeedsCase><IocsPage /></NeedsCase>} />
          <Route path="/custody" element={<CustodyPage />} />
          <Route path="/reports" element={<NeedsCase><ReportsPage /></NeedsCase>} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/login" element={<Navigate to="/" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </CaseProvider>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <Shell />
      </AuthProvider>
    </ToastProvider>
  );
}
