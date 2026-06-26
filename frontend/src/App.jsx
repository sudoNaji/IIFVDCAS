import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import DeviceDetection from './pages/DeviceDetection'
import FirmwareExtraction from './pages/FirmwareExtraction'
import StaticAnalysis from './pages/StaticAnalysis'
import SBOM from './pages/SBOM'
import CvePage from './pages/CvePage'
import VEXPage from './pages/VEXPage'
import CompliancePage from './pages/CompliancePage'
import AISettings from './pages/AISettings'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard"  element={<Dashboard />} />
        <Route path="devices"    element={<DeviceDetection />} />
        <Route path="firmware"   element={<FirmwareExtraction />} />
        <Route path="analysis"   element={<StaticAnalysis />} />
        <Route path="sbom"       element={<SBOM />} />
        <Route path="cve"        element={<CvePage />} />
        <Route path="vex"        element={<VEXPage />} />
        <Route path="compliance" element={<CompliancePage />} />
        <Route path="ai-settings" element={<AISettings />} />
      </Route>
    </Routes>
  )
}
