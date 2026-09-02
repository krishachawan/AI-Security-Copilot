import { useEffect, useRef, useState } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [filename, setFilename] = useState("untitled.py");
  const [code, setCode] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [backendConnected, setBackendConnected] = useState(false);

  const fileInputRef = useRef(null);

  // --------------------------------------------------
  // Check backend connection
  // --------------------------------------------------
  useEffect(() => {
    const checkBackend = async () => {
      try {
        const response = await fetch(`${API_URL}/`);

        if (response.ok) {
          setBackendConnected(true);
        } else {
          setBackendConnected(false);
        }
      } catch {
        setBackendConnected(false);
      }
    };

    checkBackend();

    const interval = setInterval(checkBackend, 5000);

    return () => clearInterval(interval);
  }, []);

  // --------------------------------------------------
  // Upload file
  // --------------------------------------------------
  const handleFileUpload = (event) => {
    const file = event.target.files?.[0];

    if (!file) return;

    setFilename(file.name);
    setResult(null);
    setError("");

    const reader = new FileReader();

    reader.onload = (e) => {
      setCode(e.target.result);
    };

    reader.onerror = () => {
      setError("Unable to read the selected file.");
    };

    reader.readAsText(file);
  };

  // --------------------------------------------------
  // Analyze code
  // --------------------------------------------------
  const handleAnalyze = async () => {
    if (!code.trim()) {
      setError("Please enter or upload source code first.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API_URL}/api/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          filename,
          code,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data?.detail || `Analysis failed with status ${response.status}`,
        );
      }

      setResult(data);
    } catch (err) {
      console.error(err);
      setError(err.message || "Failed to connect to the backend.");
    } finally {
      setLoading(false);
    }
  };

  // --------------------------------------------------
  // New analysis
  // --------------------------------------------------
  const handleNewAnalysis = () => {
    setResult(null);
    setError("");
  };

  // --------------------------------------------------
  // Helpers
  // --------------------------------------------------
  const getSeverityClass = (severity) => {
    if (!severity) return "";

    const value = severity.toLowerCase();

    if (value === "critical") return "severity-critical";
    if (value === "high") return "severity-high";
    if (value === "medium") return "severity-medium";
    if (value === "low") return "severity-low";

    return "";
  };

  const getVerdictLabel = (verdict) => {
    if (!verdict) return "Unknown";

    return verdict
      .replaceAll("_", " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  };

  const getCodeBertConfidence = () => {
    const confidence = result?.codebert?.confidence;

    if (typeof confidence !== "number") {
      return null;
    }

    return `${(confidence * 100).toFixed(1)}%`;
  };

  // --------------------------------------------------
  // RESULTS PAGE
  // --------------------------------------------------
  if (result) {
    const llm = result.llm;
    const sast = result.sast;
    const codebert = result.codebert;
    const rag = result.rag;

    return (
      <div className="app">
        {/* Header */}
        <header className="header">
          <div className="brand">
            <div className="brand-icon">♢</div>

            <div>
              <h1>AI Security Copilot</h1>
              <p>AI-assisted source code security analysis</p>
            </div>
          </div>

          <div className="connection-status">
            <span className="status-dot"></span>
            Backend connected
          </div>
        </header>

        <main className="results-page">
          {/* Page heading */}
          <div className="results-heading">
            <div>
              <div className="eyebrow">ANALYSIS COMPLETE</div>

              <h2>Security Analysis Results</h2>
            </div>

            <div className="filename-badge">{result.filename || filename}</div>
          </div>

          {/* Summary cards */}
          <section className="summary-grid">
            <div className="summary-card verdict-card">
              <div className="summary-icon danger">!</div>

              <div>
                <div className="summary-label">FINAL VERDICT</div>

                <div className="summary-value">
                  {getVerdictLabel(result.verdict)}
                </div>
              </div>
            </div>

            <div className="summary-card">
              <div className="summary-icon">◇</div>

              <div>
                <div className="summary-label">SEVERITY</div>

                <div
                  className={`summary-value ${getSeverityClass(llm?.severity)}`}
                >
                  {llm?.severity || "N/A"}
                </div>
              </div>
            </div>

            <div className="summary-card">
              <div className="summary-icon">○</div>

              <div>
                <div className="summary-label">CODEBERT</div>

                <div className="summary-value">
                  {codebert?.label_name
                    ? getVerdictLabel(codebert.label_name)
                    : "N/A"}
                </div>

                {getCodeBertConfidence() && (
                  <div className="summary-sub">
                    {getCodeBertConfidence()} confidence
                  </div>
                )}
              </div>
            </div>

            <div className="summary-card">
              <div className="summary-icon">◇</div>

              <div>
                <div className="summary-label">SAST FINDINGS</div>

                <div className="summary-value">
                  {sast?.summary?.total ?? sast?.findings?.length ?? 0}
                </div>
              </div>
            </div>
          </section>

          {/* Detection Pipeline */}
          <section className="section">
            <div className="eyebrow">TECHNICAL DETAILS</div>

            <h2 className="section-title">Detection Pipeline</h2>

            <div className="pipeline-card">
              <PipelineItem
                name="CodeBERT"
                status={
                  codebert?.vulnerable
                    ? "Vulnerable detected"
                    : "No vulnerability detected"
                }
                active
              />

              <PipelineItem
                name="SAST"
                status={`${sast?.findings?.length || 0} findings detected`}
                active={sast?.status === "completed"}
              />

              <PipelineItem
                name="RAG"
                status={`${rag?.retrieved_cwes?.length || 0} CWE entries retrieved`}
                active={!!rag}
              />

              <PipelineItem
                name="Gemini AI"
                status={
                  llm?.status === "completed"
                    ? "Security analysis completed"
                    : "Analysis unavailable"
                }
                active={llm?.status === "completed"}
              />
            </div>
          </section>

          {/* SAST Findings */}
          <section className="section">
            <div className="finding-card">
              <div className="finding-header">
                <div className="finding-title">
                  <span className="purple-symbol">◇</span>

                  <h3>SAST Findings</h3>

                  <span className="count-badge">
                    {sast?.findings?.length || 0}
                  </span>
                </div>

                <span className="collapse-icon">⌄</span>
              </div>

              <div className="findings-list">
                {sast?.findings?.length > 0 ? (
                  sast.findings.map((finding, index) => (
                    <SastFinding
                      key={`${finding.rule_id}-${index}`}
                      finding={finding}
                    />
                  ))
                ) : (
                  <div className="empty-state">No SAST findings detected.</div>
                )}
              </div>
            </div>
          </section>

          {/* AI Analysis */}
          {llm?.status === "completed" && (
            <section className="section">
              <div className="eyebrow">AI SECURITY ANALYSIS</div>

              <h2 className="section-title">Security Recommendation</h2>

              <div className="ai-card">
                {/* AI header */}
                <div className="ai-header">
                  <div className="ai-symbol">✦</div>

                  <div className="ai-title-area">
                    <h3>{llm.vulnerability || "Security Vulnerability"}</h3>

                    <div className="ai-meta">
                      {llm.cwe && <span className="meta-pill">{llm.cwe}</span>}

                      {llm.severity && (
                        <span
                          className={`meta-pill ${getSeverityClass(
                            llm.severity,
                          )}`}
                        >
                          {llm.severity}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Explanation */}
                {llm.explanation && (
                  <div className="analysis-block">
                    <h4>Explanation</h4>

                    <p>{llm.explanation}</p>
                  </div>
                )}

                {/* Evidence */}
                {llm.evidence?.length > 0 && (
                  <div className="analysis-block">
                    <h4>Evidence</h4>

                    <ul className="evidence-list">
                      {llm.evidence.map((item, index) => (
                        <li key={index}>{item}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Impact */}
                {llm.impact && (
                  <div className="analysis-block">
                    <h4>Impact</h4>

                    <p>{llm.impact}</p>
                  </div>
                )}

                {/* RECOMMENDED FIX */}
                {llm.remediation?.length > 0 && (
                  <div className="analysis-block recommended-fix">
                    <div className="fix-heading">
                      <div className="fix-icon">✓</div>

                      <h4>Recommended Fix</h4>
                    </div>

                    <ol className="remediation-list">
                      {llm.remediation.map((fix, index) => (
                        <li key={index}>
                          <span>{fix}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                )}

                {/* Secure Code */}
                {llm.secure_code && (
                  <div className="analysis-block">
                    <h4>Secure Code</h4>

                    <div className="code-container">
                      <div className="code-header">
                        <span>SECURE IMPLEMENTATION</span>

                        <button
                          onClick={() =>
                            navigator.clipboard.writeText(llm.secure_code)
                          }
                        >
                          Copy
                        </button>
                      </div>

                      <pre>
                        <code>{llm.secure_code}</code>
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* RAG Context */}
          {rag?.retrieved_cwes?.length > 0 && (
            <section className="section">
              <div className="eyebrow">KNOWLEDGE RETRIEVAL</div>

              <h2 className="section-title">RAG Context</h2>

              <div className="rag-card">
                <div className="rag-header">
                  <span className="rag-symbol">◈</span>

                  <div>
                    <h3>Retrieved CWE Knowledge</h3>

                    <p>
                      Relevant vulnerability knowledge retrieved from the
                      security knowledge base.
                    </p>
                  </div>
                </div>

                <div className="cwe-list">
                  {rag.retrieved_cwes.map((cwe, index) => (
                    <div className="cwe-item" key={index}>
                      <div>
                        <strong>{cwe.cwe_id}</strong>

                        <span>{cwe.cwe_name}</span>
                      </div>

                      {typeof cwe.semantic_score === "number" && (
                        <span className="score">
                          {(cwe.semantic_score * 100).toFixed(1)}%
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </section>
          )}

          {/* Analyze another file */}
          <div className="bottom-actions">
            <button className="secondary-button" onClick={handleNewAnalysis}>
              ← Analyze Another File
            </button>
          </div>
        </main>
      </div>
    );
  }

  // --------------------------------------------------
  // INPUT PAGE
  // --------------------------------------------------
  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="brand">
          <div className="brand-icon">♢</div>

          <div>
            <h1>AI Security Copilot</h1>
            <p>AI-assisted source code security analysis</p>
          </div>
        </div>

        <div className="connection-status">
          <span
            className={`status-dot ${backendConnected ? "" : "disconnected"}`}
          ></span>

          {backendConnected ? "Backend connected" : "Backend disconnected"}
        </div>
      </header>

      <main className="main-content">
        {/* Hero */}
        <section className="hero-section">
          <div className="eyebrow">AI-POWERED SECURITY ANALYSIS</div>

          <h2>
            Find vulnerabilities.
            <br />
            <span>Fix them intelligently.</span>
          </h2>

          <p>
            Analyze source code using CodeBERT, SAST scanners, RAG-based
            security knowledge, and Gemini AI.
          </p>
        </section>

        {/* Source code */}
        <section className="source-card">
          <div className="source-header">
            <div>
              <div className="eyebrow">SOURCE CODE</div>

              <h3>Analyze your code</h3>

              <p>
                Paste your source code or upload a file for security analysis.
              </p>
            </div>

            <button
              className="upload-button"
              onClick={() => fileInputRef.current?.click()}
            >
              ↑ Upload File
            </button>

            <input
              ref={fileInputRef}
              type="file"
              hidden
              onChange={handleFileUpload}
              accept=".py,.js,.jsx,.ts,.tsx,.java,.c,.cpp,.cs,.php,.go,.rb,.rs,.swift,.kt,.sql"
            />
          </div>

          {/* Filename */}
          <div className="filename-row">
            <span>▣</span>

            <span>{filename}</span>
          </div>

          {/* Editor */}
          <textarea
            className="code-editor"
            value={code}
            onChange={(e) => {
              setCode(e.target.value);
              setResult(null);
            }}
            placeholder={`Paste your source code here...

Example:

import subprocess

def run_command(request_data):
    command = request_data.get("command")
    result = subprocess.run(
        command,
        shell=True
    )

    return result.stdout`}
            spellCheck="false"
          />

          {/* Error */}
          {error && (
            <div className="error-message">
              <span>⚠</span>

              <span>{error}</span>
            </div>
          )}

          {/* Analyze */}
          <button
            className="analyze-button"
            onClick={handleAnalyze}
            disabled={loading || !code.trim()}
          >
            {loading ? (
              <>
                <span className="spinner"></span>
                Analyzing Code...
              </>
            ) : (
              <>✦ Analyze Code</>
            )}
          </button>
        </section>

        {/* Pipeline explanation */}
        <section className="info-section">
          <div className="eyebrow">MULTI-STAGE ANALYSIS</div>

          <h2>How it works</h2>

          <div className="info-grid">
            <InfoCard
              number="01"
              title="CodeBERT"
              text="ML-based vulnerability classification of the submitted source code."
            />

            <InfoCard
              number="02"
              title="SAST"
              text="Semgrep and Bandit identify rule-based security findings."
            />

            <InfoCard
              number="03"
              title="RAG"
              text="Relevant CWE security knowledge is retrieved from the knowledge base."
            />

            <InfoCard
              number="04"
              title="Gemini AI"
              text="Generates an explanation, impact assessment, remediation, and secure code."
            />
          </div>
        </section>
      </main>
    </div>
  );
}

// ==================================================
// PIPELINE ITEM
// ==================================================

function PipelineItem({ name, status, active }) {
  return (
    <div className="pipeline-item">
      <div className={`pipeline-check ${active ? "active" : ""}`}>
        {active ? "✓" : "•"}
      </div>

      <div className="pipeline-info">
        <strong>{name}</strong>

        <span>{status}</span>
      </div>
    </div>
  );
}

// ==================================================
// SAST FINDING
// ==================================================

function SastFinding({ finding }) {
  return (
    <div className="sast-finding">
      <div className="finding-top">
        <div className="finding-left">
          <span className="tool-badge">{finding.tool?.toUpperCase()}</span>

          <strong>{finding.rule_id}</strong>
        </div>

        <span
          className={`finding-severity ${getSeverityStaticClass(
            finding.severity,
          )}`}
        >
          {finding.severity}
        </span>
      </div>

      <p className="finding-message">{finding.message}</p>

      <div className="finding-meta">
        {finding.cwe && <span className="meta-tag">{finding.cwe}</span>}

        {finding.owasp && <span className="meta-tag">{finding.owasp}</span>}

        {finding.line && <span className="meta-tag">Line {finding.line}</span>}

        {finding.confidence && (
          <span className="meta-tag">Confidence: {finding.confidence}</span>
        )}
      </div>
    </div>
  );
}

// ==================================================
// INFO CARD
// ==================================================

function InfoCard({ number, title, text }) {
  return (
    <div className="info-card">
      <span className="info-number">{number}</span>

      <h3>{title}</h3>

      <p>{text}</p>
    </div>
  );
}

// ==================================================
// STATIC SEVERITY CLASS
// ==================================================

function getSeverityStaticClass(severity) {
  if (!severity) return "";

  const value = severity.toLowerCase();

  if (value === "critical") return "severity-critical";
  if (value === "high" || value === "error") return "severity-high";
  if (value === "medium") return "severity-medium";
  if (value === "low") return "severity-low";

  return "";
}

export default App;
