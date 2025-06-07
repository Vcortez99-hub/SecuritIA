import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Download,
  ChevronDown,
  ChevronUp,
  Cpu,
  Lock,
  Globe,
  Database,
  Settings,
  AlertCircle,
  TrendingUp,
  Brain
} from 'lucide-react';

interface Vulnerability {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cvss_score: number;
  confidence_score: number;
  vulnerability_type: string;
  port?: number;
  service?: string;
  description: string;
  impact: string;
  recommendation: string;
  evidence?: string;
  ai_recommendations?: string[];
  attack_vectors?: string[];
}

interface ScanResult {
  scan_id: string;
  target: string;
  status: string;
  started_at: string;
  completed_at?: string;
  scan_type: string;
  risk_score: number;
  vulnerabilities: Vulnerability[];
  services: Record<string, any>;
  open_ports: number[];
  ssl_analysis: Record<string, any>;
  web_analysis: Record<string, any>;
  ai_analysis: {
    risk_prioritization: any[];
    attack_chain_analysis: any[];
    remediation_roadmap: any[];
    business_impact_assessment: any;
    ai_insights: string[];
  };
  executive_summary: {
    overall_risk_level: string;
    key_findings: string[];
    business_impact_assessment: string;
    immediate_actions: string[];
    strategic_recommendations: string[];
  };
  summary: {
    total_vulnerabilities: number;
    severity_distribution: Record<string, number>;
    open_ports: number;
    services_detected: number;
    scan_duration: string;
    risk_level: string;
    top_risks: string[];
    ai_confidence: number;
  };
}

const ScanResults: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    executive: true,
    vulnerabilities: true,
    services: false,
    ssl: false,
    ai: false,
  });

  useEffect(() => {
    fetchScanResult();
    const interval = setInterval(fetchScanResult, 5000);
    return () => clearInterval(interval);
  }, [scanId]);

  const fetchScanResult = async () => {
    try {
      const response = await fetch(`http://localhost:8000/api/scans/${scanId}`);
      if (!response.ok) throw new Error('Failed to fetch scan results');
      const data = await response.json();
      setScanResult(data);
      setLoading(false);
      
      // Stop polling if scan is completed
      if (data.status === 'completed' || data.status === 'failed') {
        setLoading(false);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
      setLoading(false);
    }
  };

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-600 bg-red-100';
      case 'HIGH': return 'text-orange-600 bg-orange-100';
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-100';
      case 'LOW': return 'text-blue-600 bg-blue-100';
      case 'INFO': return 'text-gray-600 bg-gray-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return <XCircle className="w-5 h-5" />;
      case 'HIGH': return <AlertTriangle className="w-5 h-5" />;
      case 'MEDIUM': return <AlertCircle className="w-5 h-5" />;
      case 'LOW': return <Info className="w-5 h-5" />;
      case 'INFO': return <Info className="w-5 h-5" />;
      default: return <Info className="w-5 h-5" />;
    }
  };

  const getRiskLevelColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'text-red-600';
      case 'HIGH': return 'text-orange-600';
      case 'MEDIUM': return 'text-yellow-600';
      case 'LOW': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  const getVulnerabilityTypeIcon = (type: string) => {
    switch (type) {
      case 'sql_injection': return <Database className="w-4 h-4" />;
      case 'xss': return <Globe className="w-4 h-4" />;
      case 'ssl': return <Lock className="w-4 h-4" />;
      case 'configuration': return <Settings className="w-4 h-4" />;
      case 'service_exposure': return <Cpu className="w-4 h-4" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  if (loading && !scanResult) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Scanning in progress...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center text-red-600">
          <XCircle className="w-12 h-12 mx-auto mb-4" />
          <p>Error: {error}</p>
        </div>
      </div>
    );
  }

  if (!scanResult) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <p className="text-gray-600">No scan results found</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="bg-white shadow-sm rounded-lg p-6 mb-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Scan Results</h1>
              <p className="text-gray-600 mt-1">Target: {scanResult.target}</p>
            </div>
            <div className="flex items-center space-x-4">
              <div className={`px-4 py-2 rounded-lg ${scanResult.status === 'completed' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}`}>
                {scanResult.status === 'completed' ? <CheckCircle className="w-5 h-5 inline mr-2" /> : null}
                {scanResult.status}
              </div>
              <button
                onClick={() => navigate('/scans')}
                className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
              >
                Back to Scans
              </button>
            </div>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="bg-white shadow-sm rounded-lg mb-6">
          <div
            className="p-6 border-b cursor-pointer"
            onClick={() => toggleSection('executive')}
          >
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold flex items-center">
                <Brain className="w-5 h-5 mr-2 text-indigo-600" />
                AI Executive Summary
              </h2>
              {expandedSections.executive ? <ChevronUp /> : <ChevronDown />}
            </div>
          </div>
          
          {expandedSections.executive && scanResult.executive_summary && (
            <div className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="font-medium text-gray-900 mb-2">Overall Risk Level</h3>
                  <p className={`text-2xl font-bold ${getRiskLevelColor(scanResult.executive_summary.overall_risk_level)}`}>
                    {scanResult.executive_summary.overall_risk_level}
                  </p>
                </div>
                <div>
                  <h3 className="font-medium text-gray-900 mb-2">AI Confidence</h3>
                  <div className="flex items-center">
                    <div className="flex-1 bg-gray-200 rounded-full h-2">
                      <div
                        className="bg-indigo-600 h-2 rounded-full"
                        style={{ width: `${(scanResult.summary?.ai_confidence || 0) * 100}%` }}
                      />
                    </div>
                    <span className="ml-2 text-sm text-gray-600">
                      {((scanResult.summary?.ai_confidence || 0) * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>
              </div>

              <div className="mt-6">
                <h3 className="font-medium text-gray-900 mb-2">Key Findings</h3>
                <ul className="list-disc list-inside space-y-1">
                  {scanResult.executive_summary.key_findings.map((finding, idx) => (
                    <li key={idx} className="text-gray-700">{finding}</li>
                  ))}
                </ul>
              </div>

              <div className="mt-6">
                <h3 className="font-medium text-gray-900 mb-2">Business Impact</h3>
                <p className="text-gray-700">{scanResult.executive_summary.business_impact_assessment}</p>
              </div>

              <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="font-medium text-gray-900 mb-2">Immediate Actions</h3>
                  <ul className="list-disc list-inside space-y-1">
                    {scanResult.executive_summary.immediate_actions.map((action, idx) => (
                      <li key={idx} className="text-gray-700">{action}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h3 className="font-medium text-gray-900 mb-2">Strategic Recommendations</h3>
                  <ul className="list-disc list-inside space-y-1">
                    {scanResult.executive_summary.strategic_recommendations.slice(0, 3).map((rec, idx) => (
                      <li key={idx} className="text-gray-700">{rec}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Statistics Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-white p-6 rounded-lg shadow-sm">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Total Vulnerabilities</p>
                <p className="text-2xl font-bold text-gray-900">
                  {scanResult.summary?.total_vulnerabilities || 0}
                </p>
              </div>
              <Shield className="w-8 h-8 text-indigo-600" />
            </div>
          </div>
          
          <div className="bg-white p-6 rounded-lg shadow-sm">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Critical Issues</p>
                <p className="text-2xl font-bold text-red-600">
                  {scanResult.summary?.severity_distribution?.CRITICAL || 0}
                </p>
              </div>
              <XCircle className="w-8 h-8 text-red-600" />
            </div>
          </div>
          
          <div className="bg-white p-6 rounded-lg shadow-sm">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Open Ports</p>
                <p className="text-2xl font-bold text-gray-900">
                  {scanResult.summary?.open_ports || 0}
                </p>
              </div>
              <Cpu className="w-8 h-8 text-blue-600" />
            </div>
          </div>
          
          <div className="bg-white p-6 rounded-lg shadow-sm">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Risk Score</p>
                <p className="text-2xl font-bold text-orange-600">
                  {scanResult.risk_score?.toFixed(1) || '0.0'}
                </p>
              </div>
              <TrendingUp className="w-8 h-8 text-orange-600" />
            </div>
          </div>
        </div>

        {/* Vulnerabilities Section */}
        <div className="bg-white shadow-sm rounded-lg mb-6">
          <div
            className="p-6 border-b cursor-pointer"
            onClick={() => toggleSection('vulnerabilities')}
          >
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold flex items-center">
                <AlertTriangle className="w-5 h-5 mr-2 text-red-600" />
                Vulnerabilities ({scanResult.vulnerabilities?.length || 0})
              </h2>
              {expandedSections.vulnerabilities ? <ChevronUp /> : <ChevronDown />}
            </div>
          </div>
          
          {expandedSections.vulnerabilities && (
            <div className="p-6">
              {scanResult.vulnerabilities && scanResult.vulnerabilities.length > 0 ? (
                <div className="space-y-4">
                  {scanResult.vulnerabilities.map((vuln) => (
                    <div key={vuln.id} className="border rounded-lg p-4 hover:bg-gray-50">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center">
                            {getVulnerabilityTypeIcon(vuln.vulnerability_type)}
                            <h3 className="ml-2 font-medium text-gray-900">{vuln.name}</h3>
                            <span className={`ml-3 px-2 py-1 text-xs rounded-full ${getSeverityColor(vuln.severity)}`}>
                              {getSeverityIcon(vuln.severity)}
                              <span className="ml-1">{vuln.severity}</span>
                            </span>
                          </div>
                          
                          <p className="mt-2 text-gray-600">{vuln.description}</p>
                          
                          <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                              <p className="text-sm font-medium text-gray-700">Impact</p>
                              <p className="text-sm text-gray-600">{vuln.impact}</p>
                            </div>
                            <div>
                              <p className="text-sm font-medium text-gray-700">CVSS Score</p>
                              <p className="text-sm text-gray-600">{vuln.cvss_score}</p>
                            </div>
                          </div>
                          
                          {vuln.port && (
                            <div className="mt-2">
                              <span className="text-sm text-gray-500">Port: {vuln.port}</span>
                              {vuln.service && <span className="ml-2 text-sm text-gray-500">Service: {vuln.service}</span>}
                            </div>
                          )}
                          
                          <div className="mt-3">
                            <p className="text-sm font-medium text-gray-700">Recommendation</p>
                            <p className="text-sm text-gray-600">{vuln.recommendation}</p>
                          </div>
                          
                          {vuln.ai_recommendations && vuln.ai_recommendations.length > 0 && (
                            <div className="mt-3">
                              <p className="text-sm font-medium text-gray-700 flex items-center">
                                <Brain className="w-4 h-4 mr-1" />
                                AI Recommendations
                              </p>
                              <ul className="mt-1 list-disc list-inside text-sm text-gray-600">
                                {vuln.ai_recommendations.map((rec, idx) => (
                                  <li key={idx}>{rec}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                        
                        <div className="ml-4 flex items-center">
                          <div className="text-center">
                            <p className="text-xs text-gray-500">AI Confidence</p>
                            <p className="text-lg font-semibold text-indigo-600">
                              {(vuln.confidence_score * 100).toFixed(0)}%
                            </p>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <CheckCircle className="w-12 h-12 text-green-600 mx-auto mb-4" />
                  <p className="text-gray-600">No vulnerabilities detected!</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Services Section */}
        <div className="bg-white shadow-sm rounded-lg mb-6">
          <div
            className="p-6 border-b cursor-pointer"
            onClick={() => toggleSection('services')}
          >
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold flex items-center">
                <Cpu className="w-5 h-5 mr-2 text-blue-600" />
                Services & Ports
              </h2>
              {expandedSections.services ? <ChevronUp /> : <ChevronDown />}
            </div>
          </div>
          
          {expandedSections.services && (
            <div className="p-6">
              <div className="mb-4">
                <h3 className="font-medium text-gray-900 mb-2">Open Ports</h3>
                <div className="flex flex-wrap gap-2">
                  {scanResult.open_ports?.map((port) => (
                    <span key={port} className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm">
                      {port}
                    </span>
                  ))}
                </div>
              </div>
              
              {scanResult.services && Object.keys(scanResult.services).length > 0 && (
                <div>
                  <h3 className="font-medium text-gray-900 mb-2">Detected Services</h3>
                  <div className="space-y-2">
                    {Object.entries(scanResult.services).map(([port, service]) => (
                      <div key={port} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div>
                          <span className="font-medium">Port {port}</span>
                          <span className="ml-2 text-gray-600">
                            {service.service || 'Unknown'} 
                            {service.version && ` (${service.version})`}
                          </span>
                        </div>
                        <span className="text-sm text-gray-500">
                          {service.state || 'open'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* AI Analysis Section */}
        <div className="bg-white shadow-sm rounded-lg mb-6">
          <div
            className="p-6 border-b cursor-pointer"
            onClick={() => toggleSection('ai')}
          >
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold flex items-center">
                <Brain className="w-5 h-5 mr-2 text-indigo-600" />
                AI Analysis & Insights
              </h2>
              {expandedSections.ai ? <ChevronUp /> : <ChevronDown />}
            </div>
          </div>
          
          {expandedSections.ai && scanResult.ai_analysis && (
            <div className="p-6">
              {/* AI Insights */}
              {scanResult.ai_analysis.ai_insights && scanResult.ai_analysis.ai_insights.length > 0 && (
                <div className="mb-6">
                  <h3 className="font-medium text-gray-900 mb-2">AI Insights</h3>
                  <ul className="space-y-2">
                    {scanResult.ai_analysis.ai_insights.map((insight, idx) => (
                                              <li key={idx} className="flex items-start">
                          <Info className="w-4 h-4 text-indigo-600 mt-0.5 mr-2 flex-shrink-0" />
                          <span className="text-gray-700">{insight}</span>
                        </li>
                      ))}
                  </ul>
                </div>
              )}

              {/* Attack Chain Analysis */}
              {scanResult.ai_analysis.attack_chain_analysis && scanResult.ai_analysis.attack_chain_analysis.length > 0 && (
                <div className="mb-6">
                  <h3 className="font-medium text-gray-900 mb-2">Potential Attack Chains</h3>
                  <div className="space-y-3">
                    {scanResult.ai_analysis.attack_chain_analysis.map((chain, idx) => (
                      <div key={idx} className="border rounded-lg p-4 bg-red-50">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-medium text-red-900">{chain.chain_name}</h4>
                          <span className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(chain.severity)}`}>
                            {chain.severity}
                          </span>
                        </div>
                        <div className="space-y-1">
                          {chain.steps.map((step, stepIdx) => (
                            <div key={stepIdx} className="flex items-center text-sm text-gray-700">
                              <span className="w-6 h-6 bg-red-200 rounded-full flex items-center justify-center text-xs mr-2">
                                {stepIdx + 1}
                              </span>
                              {step}
                            </div>
                          ))}
                        </div>
                        <div className="mt-2 text-sm">
                          <span className="text-gray-600">Likelihood: </span>
                          <span className="font-medium">{chain.likelihood}</span>
                          <span className="text-gray-600 ml-3">Impact: </span>
                          <span className="font-medium">{chain.impact}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Remediation Roadmap */}
              {scanResult.ai_analysis.remediation_roadmap && scanResult.ai_analysis.remediation_roadmap.length > 0 && (
                <div>
                  <h3 className="font-medium text-gray-900 mb-2">Remediation Roadmap</h3>
                  <div className="space-y-3">
                    {scanResult.ai_analysis.remediation_roadmap.map((phase, idx) => (
                      <div key={idx} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-medium">{phase.phase}</h4>
                          <span className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(phase.priority)}`}>
                            {phase.priority}
                          </span>
                        </div>
                        <ul className="list-disc list-inside text-sm text-gray-700 space-y-1">
                          {phase.actions.map((action, actionIdx) => (
                            <li key={actionIdx}>{action}</li>
                          ))}
                        </ul>
                        <p className="mt-2 text-sm text-gray-600">
                          Vulnerabilities to address: {phase.vulnerabilities}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* SSL Analysis Section */}
        {scanResult.ssl_analysis && Object.keys(scanResult.ssl_analysis).length > 0 && (
          <div className="bg-white shadow-sm rounded-lg mb-6">
            <div
              className="p-6 border-b cursor-pointer"
              onClick={() => toggleSection('ssl')}
            >
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold flex items-center">
                  <Lock className="w-5 h-5 mr-2 text-green-600" />
                  SSL/TLS Analysis
                </h2>
                {expandedSections.ssl ? <ChevronUp /> : <ChevronDown />}
              </div>
            </div>
            
            {expandedSections.ssl && (
              <div className="p-6">
                <div className="space-y-4">
                  {Object.entries(scanResult.ssl_analysis).map(([port, analysis]: [string, any]) => (
                    <div key={port} className="border rounded-lg p-4">
                      <h3 className="font-medium mb-2">Port {port}</h3>
                      {analysis.error ? (
                        <p className="text-red-600">Error: {analysis.error}</p>
                      ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <p className="text-sm text-gray-600">Protocol Version</p>
                            <p className="font-medium">{analysis.protocol_version || 'Unknown'}</p>
                          </div>
                          <div>
                            <p className="text-sm text-gray-600">Cipher Suite</p>
                            <p className="font-medium">{analysis.cipher_suite || 'Unknown'}</p>
                          </div>
                          <div>
                            <p className="text-sm text-gray-600">Certificate Valid</p>
                            <p className="font-medium">{analysis.certificate_valid ? 'Yes' : 'No'}</p>
                          </div>
                          <div>
                            <p className="text-sm text-gray-600">Days Until Expiry</p>
                            <p className="font-medium">{analysis.days_until_expiry || 'N/A'}</p>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Scan Metadata */}
        <div className="bg-white shadow-sm rounded-lg">
          <div className="p-6">
            <h2 className="text-lg font-semibold mb-4">Scan Information</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-600">Scan Type</p>
                <p className="font-medium">{scanResult.scan_type}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600">Duration</p>
                <p className="font-medium">{scanResult.summary?.scan_duration || 'N/A'}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600">Started At</p>
                <p className="font-medium">{new Date(scanResult.started_at).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-sm text-gray-600">Completed At</p>
                <p className="font-medium">
                  {scanResult.completed_at ? new Date(scanResult.completed_at).toLocaleString() : 'In Progress'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanResults;