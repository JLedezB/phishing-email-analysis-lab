const express = require("express");
const cors = require("cors");
const axios = require("axios");
const dns = require("dns").promises;
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json({ limit: "5mb" }));

app.get("/", (req, res) => {
  res.json({ message: "Phishing Email Analysis Lab API is running" });
});

function extractHeaderValue(emailContent, headerName) {
  const regex = new RegExp(`^${headerName}:\\s*(.+)$`, "im");
  const match = emailContent.match(regex);
  return match ? match[1].trim() : "Not found";
}

function extractEmailDomain(value) {
  if (!value || value === "Not found") return null;

  const emailMatch = value.match(/[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);

  if (emailMatch) {
    return emailMatch[1].toLowerCase();
  }

  return null;
}

function parseHeaders(emailContent) {
  const authenticationResults = extractHeaderValue(
    emailContent,
    "Authentication-Results"
  );

  return {
    from: extractHeaderValue(emailContent, "From"),
    replyTo: extractHeaderValue(emailContent, "Reply-To"),
    returnPath: extractHeaderValue(emailContent, "Return-Path"),
    subject: extractHeaderValue(emailContent, "Subject"),
    received: emailContent.match(/^Received:\s*(.+)$/gim) || [],
    authenticationResults,
    authSummary: {
      spf: authenticationResults.toLowerCase().includes("spf=pass")
        ? "pass"
        : authenticationResults.toLowerCase().includes("spf=fail")
        ? "fail"
        : "unknown",
      dkim: authenticationResults.toLowerCase().includes("dkim=pass")
        ? "pass"
        : authenticationResults.toLowerCase().includes("dkim=fail")
        ? "fail"
        : "unknown",
      dmarc: authenticationResults.toLowerCase().includes("dmarc=pass")
        ? "pass"
        : authenticationResults.toLowerCase().includes("dmarc=fail")
        ? "fail"
        : "unknown",
    },
  };
}

function extractUrls(emailContent) {
  const rawUrls =
    emailContent.match(
      /\bhttps?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/g
    ) || [];

  return rawUrls
    .map((url) => url.replace(/[>,.)]+$/, ""))
    .filter((url) => {
      try {
        new URL(url);

        return (
          url.includes(".") &&
          !url.endsWith("=") &&
          !url.includes("=?UTF")
        );
      } catch {
        return false;
      }
    });
}

async function getDnsSecurityChecks(domain) {
  if (!domain) {
    return {
      domain: "Not found",
      mxRecords: [],
      spfRecords: [],
      dmarcRecords: [],
      status: "No sender domain found",
    };
  }

  const result = {
    domain,
    mxRecords: [],
    spfRecords: [],
    dmarcRecords: [],
    status: "Checked",
  };

  try {
    const mx = await dns.resolveMx(domain);
    result.mxRecords = mx.map((record) => ({
      exchange: record.exchange,
      priority: record.priority,
    }));
  } catch {
    result.mxRecords = [];
  }

  try {
    const txtRecords = await dns.resolveTxt(domain);
    result.spfRecords = txtRecords
      .map((record) => record.join(""))
      .filter((record) => record.toLowerCase().startsWith("v=spf1"));
  } catch {
    result.spfRecords = [];
  }

  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
    result.dmarcRecords = dmarcRecords
      .map((record) => record.join(""))
      .filter((record) => record.toLowerCase().startsWith("v=dmarc1"));
  } catch {
    result.dmarcRecords = [];
  }

  return result;
}

function buildHeaderSecuritySummary(headers, dnsChecks) {
  const issues = [];

  if (headers.authSummary.spf === "fail") {
    issues.push("SPF failed");
  }

  if (headers.authSummary.dkim === "fail") {
    issues.push("DKIM failed");
  }

  if (headers.authSummary.dmarc === "fail") {
    issues.push("DMARC failed");
  }

  if (!dnsChecks.spfRecords.length) {
    issues.push("No SPF record found for sender domain");
  }

  if (!dnsChecks.dmarcRecords.length) {
    issues.push("No DMARC record found for sender domain");
  }

  if (!dnsChecks.mxRecords.length) {
    issues.push("No MX records found for sender domain");
  }

  return {
    spf: headers.authSummary.spf,
    dkim: headers.authSummary.dkim,
    dmarc: headers.authSummary.dmarc,
    receivedHops: headers.received.length,
    dnsIssues: issues,
    status: issues.length > 0 ? "Review Required" : "Looks Healthy",
  };
}

async function scanUrlWithUrlScan(url) {
  if (!process.env.URLSCAN_API_KEY) {
    return {
      url,
      status: "API key missing",
      result: null,
    };
  }

  try {
    const response = await axios.post(
      "https://urlscan.io/api/v1/scan/",
      {
        url,
        visibility: "unlisted",
      },
      {
        headers: {
          "API-Key": process.env.URLSCAN_API_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    return {
      url,
      status: "Submitted",
      uuid: response.data.uuid,
      result: response.data.result,
      api: response.data.api,
      visibility: response.data.visibility,
    };
  } catch (error) {
    return {
      url,
      status: "Failed",
      error: error.response?.data?.message || error.message,
    };
  }
}

function encodeUrlForVirusTotal(url) {
  return Buffer.from(url)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function checkUrlWithVirusTotal(url) {
  if (!process.env.VIRUSTOTAL_API_KEY) {
    return {
      url,
      status: "API key missing",
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      reputation: "Unknown",
    };
  }

  try {
    const encodedUrl = encodeUrlForVirusTotal(url);

    const response = await axios.get(
      `https://www.virustotal.com/api/v3/urls/${encodedUrl}`,
      {
        headers: {
          "x-apikey": process.env.VIRUSTOTAL_API_KEY,
        },
      }
    );

    const stats = response.data.data.attributes.last_analysis_stats || {};

    return {
      url,
      status: "Found",
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      reputation:
        (stats.malicious || 0) > 0 || (stats.suspicious || 0) > 0
          ? "Suspicious/Malicious"
          : "Clean/No detections",
      link: `https://www.virustotal.com/gui/url/${encodedUrl}`,
    };
  } catch (error) {
    return {
      url,
      status: "Failed",
      error:
        error.response?.data?.error?.message ||
        error.response?.data?.message ||
        error.message,
    };
  }
}

app.post("/analyze", async (req, res) => {
  const { emailContent } = req.body;

  if (!emailContent || !emailContent.trim()) {
    return res.status(400).json({ error: "Email content is required" });
  }

  const indicators = [];
  let riskScore = 0;

  const lowerEmail = emailContent.toLowerCase();
  const headers = parseHeaders(emailContent);
  const senderDomain = extractEmailDomain(headers.from);
  const dnsChecks = await getDnsSecurityChecks(senderDomain);
  const headerSecuritySummary = buildHeaderSecuritySummary(headers, dnsChecks);

  if (headers.from !== "Not found" && headers.returnPath !== "Not found") {
    const fromDomain = extractEmailDomain(headers.from);
    const returnPathDomain = extractEmailDomain(headers.returnPath);

    if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
      indicators.push("From and Return-Path domains do not match");
      riskScore += 20;
    }
  }

  if (headers.replyTo !== "Not found" && headers.from !== "Not found") {
    const fromDomain = extractEmailDomain(headers.from);
    const replyToDomain = extractEmailDomain(headers.replyTo);

    if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
      indicators.push("Reply-To domain differs from From domain");
      riskScore += 20;
    }
  }

  if (lowerEmail.includes("urgent")) {
    indicators.push("Uses urgent language");
    riskScore += 15;
  }

  if (lowerEmail.includes("verify your account")) {
    indicators.push("Requests account verification");
    riskScore += 25;
  }

  if (lowerEmail.includes("password")) {
    indicators.push("Mentions password or credentials");
    riskScore += 20;
  }

  if (lowerEmail.includes("login")) {
    indicators.push("Contains login-related wording");
    riskScore += 15;
  }

  if (lowerEmail.includes("bank")) {
    indicators.push("Mentions banking-related content");
    riskScore += 15;
  }

  if (lowerEmail.includes("crypto")) {
    indicators.push("Mentions cryptocurrency");
    riskScore += 20;
  }

  if (lowerEmail.includes("click below")) {
    indicators.push("Encourages link clicking");
    riskScore += 15;
  }

  if (lowerEmail.includes("limited time")) {
    indicators.push("Uses pressure tactics");
    riskScore += 15;
  }

  if (lowerEmail.includes("suspended")) {
    indicators.push("Threatens account suspension");
    riskScore += 20;
  }

  if (headers.authSummary.spf === "fail") {
    indicators.push("SPF authentication failed");
    riskScore += 30;
  }

  if (headers.authSummary.dkim === "fail") {
    indicators.push("DKIM authentication failed");
    riskScore += 30;
  }

  if (headers.authSummary.dmarc === "fail") {
    indicators.push("DMARC authentication failed");
    riskScore += 30;
  }

  if (!dnsChecks.spfRecords.length && senderDomain) {
    indicators.push("Sender domain has no visible SPF record");
    riskScore += 10;
  }

  if (!dnsChecks.dmarcRecords.length && senderDomain) {
    indicators.push("Sender domain has no visible DMARC record");
    riskScore += 10;
  }

  const urls = extractUrls(emailContent);

  if (urls.length > 0) {
    indicators.push(`Contains ${urls.length} URL(s)`);
    riskScore += 20;
  }

  const suspiciousUrls = urls.filter((url) => {
    const cleanUrl = url.toLowerCase();

    return (
      cleanUrl.includes("bit.ly") ||
      cleanUrl.includes("tinyurl") ||
      cleanUrl.includes("free") ||
      cleanUrl.includes("login") ||
      cleanUrl.includes("verify") ||
      cleanUrl.includes("secure")
    );
  });

  if (suspiciousUrls.length > 0) {
    indicators.push("Contains suspicious or shortened URLs");
    riskScore += 25;
  }

  const urlsToScan = suspiciousUrls.length > 0 ? suspiciousUrls : urls;
  const limitedUrlsToScan = urlsToScan.slice(0, 3);

  const urlScanResults = await Promise.all(
    limitedUrlsToScan.map((url) => scanUrlWithUrlScan(url))
  );

  const virusTotalResults = await Promise.all(
    limitedUrlsToScan.map((url) => checkUrlWithVirusTotal(url))
  );

  virusTotalResults.forEach((result) => {
    if (result.malicious > 0 || result.suspicious > 0) {
      indicators.push(
        `VirusTotal detected suspicious activity for URL: ${result.url}`
      );
      riskScore += 30;
    }
  });

  riskScore = Math.min(riskScore, 100);

  let verdict = "Low Risk";

  if (riskScore >= 70) {
    verdict = "High Risk";
  } else if (riskScore >= 40) {
    verdict = "Medium Risk";
  }

  res.json({
    verdict,
    riskScore,
    indicators,
    urls,
    suspiciousUrls,
    headers,
    dnsChecks,
    headerSecuritySummary,
    urlScanResults,
    virusTotalResults,
  });
});

app.listen(5000, () => {
  console.log("Backend running on http://localhost:5000");
});