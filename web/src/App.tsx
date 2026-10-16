import { useState } from 'react'
import axios from 'axios'
import './App.css'
interface Finding {
  rule_id: string;
  name: string;
  severity: string;
  description: string;
  evidence: any;
}
interface AnalysisResponse {
  status: string;
  total_flows: number;
  total_findings: number;
  findings: Finding[];
}
function App() {
  const [pcapPath, setPcapPath] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AnalysisResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const handleAnalyze = async () => {
    if (!pcapPath) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const response = await axios.post('http://127.0.0.1:8000/api/v1/analyze', {
        pcap_path: pcapPath
      });
      setResult(response.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || "An unexpected error occurred.");
    } finally {
      setLoading(false);
    }
  }
  return (
    <div className="container">
      <h1>WireTally Workbench</h1>
      <p>Defensive Network Analysis Local Service</p>
      <div className="input-group">
        <input 
          type="text" 
          value={pcapPath}
          onChange={(e) => setPcapPath(e.target.value)}
          placeholder="Enter absolute path to PCAP/PCAPNG (e.g., D:\captures\traffic.pcap)" 
          style={{ width: '400px', padding: '8px' }}
        />
        <button onClick={handleAnalyze} disabled={loading} style={{ padding: '8px 16px', marginLeft: '8px' }}>
          {loading ? 'Analyzing...' : 'Analyze PCAP'}
        </button>
      </div>
      {error && (
        <div style={{ color: 'red', marginTop: '20px', padding: '10px', border: '1px solid red' }}>
          <strong>Error:</strong> {error}
        </div>
      )}
      {result && (
        <div className="results" style={{ marginTop: '30px', textAlign: 'left' }}>
          <h2>Analysis Summary</h2>
          <p><strong>Status:</strong> {result.status}</p>
          <p><strong>Total Flows:</strong> {result.total_flows}</p>
          <p><strong>Total Findings:</strong> {result.total_findings}</p>
          {result.findings.length > 0 && (
            <>
              <h3>Findings</h3>
              {result.findings.map((finding, idx) => (
                <div key={idx} style={{ border: '1px solid #ccc', padding: '10px', marginBottom: '10px', borderRadius: '4px' }}>
                  <h4 style={{ margin: '0 0 10px 0' }}>[{finding.rule_id}] {finding.name} <span style={{ color: finding.severity === 'MEDIUM' ? 'orange' : 'inherit' }}>({finding.severity})</span></h4>
                  <p><strong>Description:</strong> {finding.description}</p>
                  <pre style={{ background: '#f4f4f4', padding: '10px', overflowX: 'auto', color: '#333' }}>
                    {JSON.stringify(finding.evidence, null, 2)}
                  </pre>
                </div>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  )
}
export default App
