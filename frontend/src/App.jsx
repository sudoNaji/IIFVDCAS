import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import DeviceDetection from './pages/DeviceDetection'
import PlaceholderPage from './pages/PlaceholderPage'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="devices" element={<DeviceDetection />} />
        <Route path="firmware" element={<PlaceholderPage phase={2} title="Firmware Extraction" emba="P50 · P55 · binwalk · unblob" branch="firmware-extraction" description="Extract firmware from connected devices or uploaded binary files." />} />
        <Route path="analysis" element={<PlaceholderPage phase={3} title="Static Analysis" emba="S12 · S13 · S45 · S60 · checksec" branch="static-analysis" description="Binary protection checks, weak functions, credentials, certificates." />} />
        <Route path="sbom" element={<PlaceholderPage phase={4} title="SBOM / HBOM / CBOM" emba="S08 · F15 · CycloneDX 1.5" branch="sbom-generation" description="Generate Software, Hardware, and Cryptographic Bills of Materials." />} />
        <Route path="cve" element={<PlaceholderPage phase={5} title="CVE Mapping" emba="F50 · NVD REST v2 · EPSS" branch="cve-mapping" description="Map SBOM components to NVD CVE database with CVSS v3 and EPSS." />} />
        <Route path="vex" element={<PlaceholderPage phase={6} title="VEX Risk Analysis" emba="VEX engine · CISA KEV" branch="vex-analysis" description="Classify CVEs with VEX status and calculate firmware risk score." />} />
        <Route path="compliance" element={<PlaceholderPage phase={7} title="Compliance Reporting" emba="ETSI EN 303 645 · EU CRA" branch="compliance-reporting" description="ETSI EN 303 645 and EU CRA gap analysis with PDF export." />} />
      </Route>
    </Routes>
  )
}
