import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import jsPDF from "jspdf";
import "./style.css";

const API_URL = "http://localhost:5000/analyze";

const tabs = [
  { key: "overview", label: "Overview" },
  { key: "headers", label: "Headers" },
  { key: "dns", label: "DNS Security" },
  { key: "indicators", label: "Indicators" },
  { key: "urls", label: "URLs & IOCs" },
  { key: "intel", label: "Threat Intel" },
  { key: "notes", label: "Analyst Notes" },
];

function App() {
  const [emailContent, setEmailContent] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState("");
  const [analystNotes, setAnalystNotes] = useState("");
  const [activeTab, setActiveTab] = useState("overview");
  const [copied, setCopied] = useState("");

  useEffect(() => {
    const savedNotes = localStorage.getItem("phishing-analyst-notes");
    if (savedNotes) setAnalystNotes(savedNotes);
  }, []);

  useEffect(() => {
    localStorage.setItem("phishing-analyst-notes", analystNotes);
  }, [analystNotes]);

  const safe = (value, fallback = "Not available") => {
    if (value === null || value === undefined || value === "") return fallback;
    return value;
  };

  const stats = useMemo(() => {
    if (!result) {
      return {
        indicators: 0,
        urls: 0,
        suspiciousUrls: 0,
        vtChecks: 0,
        urlscanChecks: 0,
      };
    }

    return {
      indicators: result.indicators?.length || 0,
      urls: result.urls?.length || 0,
      suspiciousUrls: result.suspiciousUrls?.length || 0,
      vtChecks: result.virusTotalResults?.length || 0,
      urlscanChecks: result.urlScanResults?.length || 0,
    };
  }, [result]);

  const getThreatLevel = () => {
    if (!result) return "No Analysis";

    const vtHits =
      result.virusTotalResults?.reduce(
        (total, item) =>
          total + (item.malicious || 0) + (item.suspicious || 0),
        0
      ) || 0;

    if (result.riskScore >= 70 || vtHits > 0) return "High";
    if (result.riskScore >= 40) return "Medium";
    return "Low";
  };

  const getBadgeClass = (value) => {
    if (
      value === "High" ||
      value === "High Risk" ||
      value === "Phishing" ||
      value === "Suspicious"
    ) {
      return "badge-danger";
    }

    if (value === "Medium" || value === "Medium Risk") {
      return "badge-warning";
    }

    return "badge-success";
  };

  const getRecommendedAction = () => {
    const level = getThreatLevel();

    if (level === "High") {
      return "Quarantine the message, block related URLs, preserve evidence, and escalate for SOC review.";
    }

    if (level === "Medium") {
      return "Review sender legitimacy, validate authentication results, and avoid opening extracted links.";
    }

    if (level === "Low") {
      return "No immediate containment required. Continue monitoring and document findings.";
    }

    return "Submit an email sample to begin analysis.";
  };

  const handleFileUpload = (event) => {
    const file = event.target.files[0];

    if (!file) return;

    if (!file.name.endsWith(".eml") && !file.name.endsWith(".txt")) {
      alert("Please upload a .eml or .txt file.");
      return;
    }

    const reader = new FileReader();

    reader.onload = (e) => {
      setEmailContent(e.target.result);
      setFileName(file.name);
      setResult(null);
      setActiveTab("overview");
    };

    reader.readAsText(file);
  };

  const analyzeEmail = async () => {
    if (!emailContent.trim()) {
      alert("Please paste an email or upload a file first.");
      return;
    }

    try {
      setLoading(true);
      setActiveTab("overview");

      const response = await axios.post(API_URL, {
        emailContent,
      });

      setResult(response.data);
    } catch (error) {
      console.error(error);
      alert("Error analyzing email. Make sure the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  const clearEmail = () => {
    setEmailContent("");
    setResult(null);
    setFileName("");
    setActiveTab("overview");
  };

  const clearNotes = () => {
    setAnalystNotes("");
    localStorage.removeItem("phishing-analyst-notes");
  };

  const copyText = async (text, label) => {
    if (!text) return;

    try {
      await navigator.clipboard.writeText(text);
      setCopied(label);

      setTimeout(() => {
        setCopied("");
      }, 1500);
    } catch (error) {
      console.error(error);
      alert("Unable to copy text.");
    }
  };

  const getIocText = () => {
    if (!result) return "";

    return [
      "=== PHISHING EMAIL IOC REPORT ===",
      "",
      `Verdict: ${safe(result.verdict)}`,
      `Risk Score: ${safe(result.riskScore, 0)}/100`,
      `Threat Level: ${getThreatLevel()}`,
      "",
      "=== EMAIL HEADERS ===",
      `From: ${safe(result.headers?.from)}`,
      `Reply-To: ${safe(result.headers?.replyTo)}`,
      `Return-Path: ${safe(result.headers?.returnPath)}`,
      `Subject: ${safe(result.headers?.subject)}`,
      `Authentication Results: ${safe(result.headers?.authenticationResults)}`,
      "",
      "=== EXTRACTED URLS ===",
      ...(result.urls?.length ? result.urls : ["No URLs found"]),
      "",
      "=== SUSPICIOUS URLS ===",
      ...(result.suspiciousUrls?.length
        ? result.suspiciousUrls
        : ["No suspicious URLs found"]),
      "",
      "=== INDICATORS ===",
      ...(result.indicators?.length ? result.indicators : ["No indicators found"]),
      "",
      "=== HEADER SECURITY SUMMARY ===",
      `SPF: ${safe(result.headerSecuritySummary?.spf, "unknown")}`,
      `DKIM: ${safe(result.headerSecuritySummary?.dkim, "unknown")}`,
      `DMARC: ${safe(result.headerSecuritySummary?.dmarc, "unknown")}`,
      `Received Hops: ${safe(result.headerSecuritySummary?.receivedHops, 0)}`,
      `Status: ${safe(result.headerSecuritySummary?.status, "Unknown")}`,
      "",
      "=== DNS CHECKS ===",
      `Domain: ${safe(result.dnsChecks?.domain, "Unknown")}`,
      `Status: ${safe(result.dnsChecks?.status, "Unknown")}`,
      `SPF Records: ${
        result.dnsChecks?.spfRecords?.join(" | ") || "None"
      }`,
      `DMARC Records: ${
        result.dnsChecks?.dmarcRecords?.join(" | ") || "None"
      }`,
      `MX Records: ${
        result.dnsChecks?.mxRecords
          ?.map((mx) => `${mx.exchange} (${mx.priority})`)
          .join(" | ") || "None"
      }`,
      "",
      "=== ANALYST NOTES ===",
      analystNotes || "No analyst notes provided.",
    ].join("\n");
  };

  const exportIOC = () => {
    if (!result) {
      alert("Analyze an email first.");
      return;
    }

    const iocData = {
      verdict: result.verdict,
      riskScore: result.riskScore,
      threatLevel: getThreatLevel(),
      recommendedAction: getRecommendedAction(),
      sender: result.headers?.from,
      replyTo: result.headers?.replyTo,
      returnPath: result.headers?.returnPath,
      subject: result.headers?.subject,
      authenticationResults: result.headers?.authenticationResults,
      indicators: result.indicators || [],
      extractedUrls: result.urls || [],
      suspiciousUrls: result.suspiciousUrls || [],
      dnsChecks: result.dnsChecks || {},
      headerSecuritySummary: result.headerSecuritySummary || {},
      urlScanResults: result.urlScanResults || [],
      virusTotalResults: result.virusTotalResults || [],
      analystNotes,
      generatedAt: new Date().toISOString(),
    };

    const blob = new Blob([JSON.stringify(iocData, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");

    a.href = url;
    a.download = "phishing-ioc-report.json";
    a.click();

    URL.revokeObjectURL(url);
  };

  const exportPDF = () => {
    if (!result) {
      alert("Analyze an email first.");
      return;
    }

    const doc = new jsPDF();
    let y = 18;

    const addTitle = (text) => {
      if (y > 260) {
        doc.addPage();
        y = 18;
      }

      doc.setFontSize(14);
      doc.text(text, 15, y);
      y += 8;
    };

    const addLine = (text) => {
      if (y > 275) {
        doc.addPage();
        y = 18;
      }

      doc.setFontSize(10);
      const lines = doc.splitTextToSize(String(text), 180);
      doc.text(lines, 15, y);
      y += lines.length * 6;
    };

    doc.setFontSize(18);
    doc.text("Phishing Email Analysis Report", 15, y);
    y += 12;

    addLine(`Generated: ${new Date().toLocaleString()}`);
    addLine(`Verdict: ${safe(result.verdict)}`);
    addLine(`Risk Score: ${safe(result.riskScore, 0)}/100`);
    addLine(`Threat Level: ${getThreatLevel()}`);
    addLine(`Recommended Action: ${getRecommendedAction()}`);

    y += 4;
    addTitle("Email Headers");
    addLine(`From: ${safe(result.headers?.from)}`);
    addLine(`Reply-To: ${safe(result.headers?.replyTo)}`);
    addLine(`Return-Path: ${safe(result.headers?.returnPath)}`);
    addLine(`Subject: ${safe(result.headers?.subject)}`);

    y += 4;
    addTitle("Indicators");
    addLine(
      result.indicators?.length
        ? result.indicators.join("\n")
        : "No indicators detected."
    );

    y += 4;
    addTitle("Suspicious URLs");
    addLine(
      result.suspiciousUrls?.length
        ? result.suspiciousUrls.join("\n")
        : "No suspicious URLs detected."
    );

    y += 4;
    addTitle("Analyst Notes");
    addLine(analystNotes || "No analyst notes provided.");

    doc.save("phishing-analysis-report.pdf");
  };

  const renderList = (items, emptyText, copyLabel) => {
    if (!items || items.length === 0) {
      return <p className="empty-state">{emptyText}</p>;
    }

    return (
      <div className="ioc-list">
        {items.map((item, index) => (
          <div className="ioc-item" key={`${copyLabel}-${index}`}>
            <span>{item}</span>

            <button
              className="mini-btn"
              onClick={() => copyText(item, `${copyLabel}-${index}`)}
            >
              {copied === `${copyLabel}-${index}` ? "Copied" : "Copy"}
            </button>
          </div>
        ))}
      </div>
    );
  };

  const renderIntelResults = (items, type) => {
    if (!items || items.length === 0) {
      return <p className="empty-state">No {type} results available.</p>;
    }

    return (
      <div className="intel-list">
        {items.map((item, index) => (
          <div className="intel-card" key={`${type}-${index}`}>
            <div className="intel-card-header">
              <strong>{item.url || item.domain || item.target || `Result ${index + 1}`}</strong>

              <button
                className="mini-btn"
                onClick={() =>
                  copyText(JSON.stringify(item, null, 2), `${type}-${index}`)
                }
              >
                {copied === `${type}-${index}` ? "Copied" : "Copy JSON"}
              </button>
            </div>

            <pre>{JSON.stringify(item, null, 2)}</pre>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div>
          <div className="brand">
            <div className="brand-icon">🛡️</div>

            <div>
              <h2>PhishTool</h2>
              <p>SOC Email Analyzer</p>
            </div>
          </div>

          <nav className="side-nav">
            {tabs.map((tab) => (
              <button
                key={tab.key}
                className={activeTab === tab.key ? "active" : ""}
                onClick={() => setActiveTab(tab.key)}
                disabled={!result && tab.key !== "overview" && tab.key !== "notes"}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        <div className="risk-widget">
          <span>Risk Summary</span>
          <h3>{result ? safe(result.verdict) : "No Analysis"}</h3>

          <div className="risk-circle">
            <strong>{result ? safe(result.riskScore, 0) : 0}</strong>
            <small>/100</small>
          </div>

          <p>{getRecommendedAction()}</p>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <span className="eyebrow">Phishing Email Analysis Lab</span>
            <h1>Professional SOC Triage Dashboard</h1>
            <p>
              Analyze suspicious emails, extract IOCs, review headers, validate
              DNS security, and export evidence.
            </p>
          </div>

          <div className="topbar-actions">
            <button
              className="btn-secondary"
              onClick={() => copyText(getIocText(), "IOCs")}
              disabled={!result}
            >
              {copied === "IOCs" ? "Copied!" : "Copy IOCs"}
            </button>

            <button className="btn-success" onClick={exportPDF} disabled={!result}>
              Export PDF
            </button>

            <button className="btn-warning" onClick={exportIOC} disabled={!result}>
              Export JSON
            </button>
          </div>
        </header>

        <section className="card input-card">
          <div className="section-title">
            <div>
              <h3>Submit Suspicious Email</h3>
              <p>Paste raw headers/body or upload a .eml/.txt sample.</p>
            </div>

            {fileName && <span className="file-pill">{fileName}</span>}
          </div>

          <div className="upload-box">
            <input
              type="file"
              className="file-input"
              accept=".eml,.txt"
              onChange={handleFileUpload}
            />

            <small>Supported formats: .eml, .txt</small>
          </div>

          <textarea
            className="email-textarea"
            rows="10"
            placeholder="Paste suspicious email headers and body here..."
            value={emailContent}
            onChange={(e) => setEmailContent(e.target.value)}
          />

          <div className="button-row">
            <button className="btn-primary" onClick={analyzeEmail} disabled={loading}>
              {loading ? (
                <>
                  <span className="spinner"></span>
                  Analyzing Email...
                </>
              ) : (
                "Analyze Email"
              )}
            </button>

            <button className="btn-ghost" onClick={clearEmail} disabled={loading}>
              Clear
            </button>
          </div>
        </section>

        {loading && (
          <section className="card loading-card">
            <span className="spinner large"></span>
            <div>
              <h3>Running analysis</h3>
              <p>Extracting headers, URLs, DNS records, and threat intelligence.</p>
            </div>
          </section>
        )}

        {result && (
          <>
            <section className="stats-grid">
              <div className="stat-card danger">
                <p>Risk Score</p>
                <h3>{safe(result.riskScore, 0)}/100</h3>
              </div>

              <div className="stat-card">
                <p>Indicators</p>
                <h3>{stats.indicators}</h3>
              </div>

              <div className="stat-card">
                <p>URLs Found</p>
                <h3>{stats.urls}</h3>
              </div>

              <div className="stat-card">
                <p>Suspicious URLs</p>
                <h3>{stats.suspiciousUrls}</h3>
              </div>

              <div className="stat-card">
                <p>VirusTotal Checks</p>
                <h3>{stats.vtChecks}</h3>
              </div>

              <div className="stat-card">
                <p>URLScan Checks</p>
                <h3>{stats.urlscanChecks}</h3>
              </div>
            </section>

            <section className="card threat-card">
              <div className="section-title">
                <div>
                  <h3>Threat Intelligence Summary</h3>
                  <p>Automated triage recommendation for analyst review.</p>
                </div>

                <span className={`custom-badge ${getBadgeClass(getThreatLevel())}`}>
                  {getThreatLevel()}
                </span>
              </div>

              <div className="threat-grid">
                <div>
                  <span>Recommended Action</span>
                  <p>{getRecommendedAction()}</p>
                </div>

                <div>
                  <span>Case Summary</span>
                  <p>
                    This message contains {stats.indicators} indicator(s),{" "}
                    {stats.urls} extracted URL(s), {stats.suspiciousUrls} suspicious
                    URL(s), {stats.vtChecks} VirusTotal result(s), and{" "}
                    {stats.urlscanChecks} URLScan result(s).
                  </p>
                </div>
              </div>
            </section>

            <section className="tabs-card">
              <div className="tabs">
                {tabs.map((tab) => (
                  <button
                    key={tab.key}
                    className={activeTab === tab.key ? "active" : ""}
                    onClick={() => setActiveTab(tab.key)}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <div className="tab-content">
                {activeTab === "overview" && (
                  <div>
                    <div className="section-title">
                      <div>
                        <h3>Analysis Overview</h3>
                        <p>High-level verdict, score, and interpretation.</p>
                      </div>

                      <span className={`custom-badge ${getBadgeClass(result.verdict)}`}>
                        {safe(result.verdict)}
                      </span>
                    </div>

                    <div className="risk-bar">
                      <div style={{ width: `${Math.min(result.riskScore || 0, 100)}%` }}></div>
                    </div>

                    <div className="overview-grid">
                      <div className="detail-card">
                        <span>Verdict</span>
                        <strong>{safe(result.verdict)}</strong>
                      </div>

                      <div className="detail-card">
                        <span>Threat Level</span>
                        <strong>{getThreatLevel()}</strong>
                      </div>

                      <div className="detail-card">
                        <span>Sender</span>
                        <strong>{safe(result.headers?.from)}</strong>
                      </div>

                      <div className="detail-card">
                        <span>Subject</span>
                        <strong>{safe(result.headers?.subject)}</strong>
                      </div>
                    </div>

                    <p className="muted">
                      Risk score is based on suspicious language, sender/header
                      mismatches, authentication failures, extracted URLs, DNS
                      posture, and threat intelligence results.
                    </p>
                  </div>
                )}

                {activeTab === "headers" && (
                  <div>
                    <div className="section-title">
                      <div>
                        <h3>Email Header Summary</h3>
                        <p>Google Admin Toolbox-style header review.</p>
                      </div>

                      <button
                        className="mini-btn"
                        onClick={() =>
                          copyText(
                            JSON.stringify(result.headers || {}, null, 2),
                            "Headers"
                          )
                        }
                      >
                        {copied === "Headers" ? "Copied!" : "Copy JSON"}
                      </button>
                    </div>

                    <div className="table-wrap">
                      <table>
                        <tbody>
                          <tr>
                            <th>From</th>
                            <td>{safe(result.headers?.from)}</td>
                          </tr>

                          <tr>
                            <th>Reply-To</th>
                            <td>{safe(result.headers?.replyTo)}</td>
                          </tr>

                          <tr>
                            <th>Return-Path</th>
                            <td>{safe(result.headers?.returnPath)}</td>
                          </tr>

                          <tr>
                            <th>Subject</th>
                            <td>{safe(result.headers?.subject)}</td>
                          </tr>

                          <tr>
                            <th>Authentication Results</th>
                            <td>{safe(result.headers?.authenticationResults)}</td>
                          </tr>

                          <tr>
                            <th>Received Hops</th>
                            <td>{result.headers?.received?.length || 0}</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>

                    <h3 className="mt">Received Path</h3>

                    {renderList(
                      result.headers?.received || [],
                      "No received headers found.",
                      "Received"
                    )}
                  </div>
                )}

                {activeTab === "dns" && (
                  <div>
                    <div className="section-title">
                      <div>
                        <h3>DNS Security Checks</h3>
                        <p>MXToolbox-style SPF, DMARC, and MX validation.</p>
                      </div>

                      <button
                        className="mini-btn"
                        onClick={() =>
                          copyText(
                            JSON.stringify(
                              {
                                dnsChecks: result.dnsChecks,
                                headerSecuritySummary:
                                  result.headerSecuritySummary,
                              },
                              null,
                              2
                            ),
                            "DNS"
                          )
                        }
                      >
                        {copied === "DNS" ? "Copied!" : "Copy JSON"}
                      </button>
                    </div>

                    <div className="table-wrap">
                      <table>
                        <tbody>
                          <tr>
                            <th>Sender Domain</th>
                            <td>{safe(result.dnsChecks?.domain, "Not found")}</td>
                          </tr>

                          <tr>
                            <th>DNS Status</th>
                            <td>{safe(result.dnsChecks?.status, "Unknown")}</td>
                          </tr>

                          <tr>
                            <th>SPF Records</th>
                            <td>
                              {result.dnsChecks?.spfRecords?.length > 0
                                ? result.dnsChecks.spfRecords.map((record, index) => (
                                    <div className="code-line" key={index}>
                                      {record}
                                    </div>
                                  ))
                                : "No SPF records found"}
                            </td>
                          </tr>

                          <tr>
                            <th>DMARC Records</th>
                            <td>
                              {result.dnsChecks?.dmarcRecords?.length > 0
                                ? result.dnsChecks.dmarcRecords.map(
                                    (record, index) => (
                                      <div className="code-line" key={index}>
                                        {record}
                                      </div>
                                    )
                                  )
                                : "No DMARC records found"}
                            </td>
                          </tr>

                          <tr>
                            <th>MX Records</th>
                            <td>
                              {result.dnsChecks?.mxRecords?.length > 0
                                ? result.dnsChecks.mxRecords.map((record, index) => (
                                    <div className="code-line" key={index}>
                                      {record.exchange} — Priority{" "}
                                      {record.priority}
                                    </div>
                                  ))
                                : "No MX records found"}
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </div>

                    <h3 className="mt">Header Authentication Summary</h3>

                    <div className="table-wrap">
                      <table>
                        <tbody>
                          <tr>
                            <th>SPF</th>
                            <td>{safe(result.headerSecuritySummary?.spf, "unknown")}</td>
                          </tr>

                          <tr>
                            <th>DKIM</th>
                            <td>{safe(result.headerSecuritySummary?.dkim, "unknown")}</td>
                          </tr>

                          <tr>
                            <th>DMARC</th>
                            <td>
                              {safe(result.headerSecuritySummary?.dmarc, "unknown")}
                            </td>
                          </tr>

                          <tr>
                            <th>Received Hops</th>
                            <td>{safe(result.headerSecuritySummary?.receivedHops, 0)}</td>
                          </tr>

                          <tr>
                            <th>Status</th>
                            <td>
                              {safe(result.headerSecuritySummary?.status, "Unknown")}
                            </td>
                          </tr>

                          <tr>
                            <th>DNS Issues</th>
                            <td>
                              {result.headerSecuritySummary?.dnsIssues?.length > 0
                                ? result.headerSecuritySummary.dnsIssues.map(
                                    (issue, index) => (
                                      <div className="danger-text" key={index}>
                                        {issue}
                                      </div>
                                    )
                                  )
                                : "No DNS issues detected"}
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {activeTab === "indicators" && (
                  <div>
                    <div className="section-title">
                      <div>
                        <h3>Detected Indicators</h3>
                        <p>Suspicious patterns found inside the email.</p>
                      </div>

                      <button
                        className="mini-btn"
                        onClick={() =>
                          copyText(
                            result.indicators?.join("\n") || "",
                            "Indicators"
                          )
                        }
                      >
                        {copied === "Indicators" ? "Copied!" : "Copy All"}
                      </button>
                    </div>

                    {renderList(
                      result.indicators || [],
                      "No obvious indicators detected.",
                      "Indicator"
                    )}
                  </div>
                )}

                {activeTab === "urls" && (
                  <div>
                    <div className="section-title">
                      <div>
                        <h3>URLs & IOCs</h3>
                        <p>Extracted links and suspicious URL findings.</p>
                      </div>

                      <button
                        className="mini-btn"
                        onClick={() =>
                          copyText(
                            [
                              "Extracted URLs:",
                              ...(result.urls || []),
                              "",
                              "Suspicious URLs:",
                              ...(result.suspiciousUrls || []),
                            ].join("\n"),
                            "URLs"
                          )
                        }
                      >
                        {copied === "URLs" ? "Copied!" : "Copy URLs"}
                      </button>
                    </div>

                    <h3>Extracted URLs</h3>

                    {renderList(result.urls || [], "No URLs extracted.", "URL")}

                    <h3 className="mt">Suspicious URLs</h3>

                    {renderList(
                      result.suspiciousUrls || [],
                      "No suspicious URLs detected.",
                      "SuspiciousURL"
                    )}
                  </div>
                )}

                {activeTab === "intel" && (
                  <div>
                    <div className="section-title">
                      <div>
                        <h3>Threat Intelligence</h3>
                        <p>VirusTotal and URLScan.io enrichment results.</p>
                      </div>

                      <button
                        className="mini-btn"
                        onClick={() =>
                          copyText(
                            JSON.stringify(
                              {
                                virusTotalResults: result.virusTotalResults || [],
                                urlScanResults: result.urlScanResults || [],
                              },
                              null,
                              2
                            ),
                            "ThreatIntel"
                          )
                        }
                      >
                        {copied === "ThreatIntel" ? "Copied!" : "Copy JSON"}
                      </button>
                    </div>

                    <div className="intel-grid">
                      <div>
                        <h3>VirusTotal Results</h3>
                        {renderIntelResults(
                          result.virusTotalResults || [],
                          "VirusTotal"
                        )}
                      </div>

                      <div>
                        <h3>URLScan.io Results</h3>
                        {renderIntelResults(result.urlScanResults || [], "URLScan")}
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === "notes" && (
                  <div>
                    <div className="section-title">
                      <div>
                        <h3>Analyst Notes</h3>
                        <p>Document investigation notes and case decisions.</p>
                      </div>

                      <div className="mini-actions">
                        <button
                          className="mini-btn"
                          onClick={() => copyText(analystNotes, "Notes")}
                        >
                          {copied === "Notes" ? "Copied!" : "Copy"}
                        </button>

                        <button className="mini-btn danger" onClick={clearNotes}>
                          Clear
                        </button>
                      </div>
                    </div>

                    <textarea
                      className="notes-textarea"
                      rows="10"
                      placeholder="Example: Sender domain does not align with Reply-To. URL redirects to suspicious login page. Recommend quarantine and user notification."
                      value={analystNotes}
                      onChange={(e) => setAnalystNotes(e.target.value)}
                    />

                    <p className="muted">
                      Notes are saved locally in your browser using localStorage.
                    </p>
                  </div>
                )}
              </div>
            </section>
          </>
        )}

        {!result && !loading && (
          <section className="card empty-dashboard">
            <h3>No analysis yet</h3>
            <p>
              Paste or upload a suspicious email, then run the analyzer to view
              the SOC dashboard, IOCs, DNS checks, and reports.
            </p>
          </section>
        )}

        <footer className="footer">
          <span>PhishTool • SOC Portfolio Project</span>
          <span>React + Node.js • IOC Export • Threat Intelligence</span>
        </footer>
      </main>
    </div>
  );
}

export default App;