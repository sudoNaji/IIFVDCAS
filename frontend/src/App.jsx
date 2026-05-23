import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import DeviceDetection from './pages/DeviceDetection'
import FirmwareExtraction from './pages/FirmwareExtraction'
import PlaceholderPage from './pages/PlaceholderPage'
import StaticAnalysis from './pages/StaticAnalysis'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="devices" element={<DeviceDetection />} />
        <Route path="firmware" element={<FirmwareExtraction />} />
        <Route path="analysis" element={<StaticAnalysis />} />
        <Route path="sbom" element={<PlaceholderPage phase={4} title="SBOM / HBOM / CBOM" emba="S08 · F15 · CycloneDX 1.5" branch="sbom-generation" description="Generate Software, Hardware, and Cryptographic Bills of Materials." />} />
        <Route path="cve" element={<PlaceholderPage phase={5} title="CVE Mapping" emba="F50 · NVD REST v2 · EPSS" branch="cve-mapping" description="Map SBOM components to NVD CVE database with CVSS v3 and EPSS." />} />
        <Route path="vex" element={<PlaceholderPage phase={6} title="VEX Risk Analysis" emba="VEX engine · CISA KEV" branch="vex-analysis" description="Classify CVEs with VEX status and calculate firmware risk score." />} />
        <Route path="compliance" element={<PlaceholderPage phase={7} title="Compliance Reporting" emba="ETSI EN 303 645 · EU CRA" branch="compliance-reporting" description="ETSI EN 303 645 and EU CRA gap analysis with PDF export." />} />
      </Route>
    </Routes>
  )
}
