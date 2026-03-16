import type { Metadata, Viewport } from "next";
import { Analytics } from "@vercel/analytics/next";
import "./globals.css";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export const metadata: Metadata = {
  title: "ThreatLens — Ask your security stack anything",
  description:
    "Browser-native security knowledge platform. Index MITRE ATT&CK, Sigma rules, CVEs, NIST 800-53, code repos. Chat across all sources with cross-domain retrieval. No server, everything local.",
  keywords:
    "security, MITRE ATT&CK, Sigma rules, CVE, NVD, NIST 800-53, threat intelligence, detection engineering, compliance, RAG, browser-native, local AI",
  openGraph: {
    title: "ThreatLens — Ask your security stack anything",
    description:
      "Index security knowledge sources in your browser. Cross-domain RAG across ATT&CK, Sigma, CVEs, NIST, and code. Everything local.",
    type: "website",
    siteName: "ThreatLens",
  },
  twitter: {
    card: "summary_large_image",
    title: "ThreatLens — Ask your security stack anything",
    description:
      "Browser-native security knowledge platform with cross-domain retrieval.",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      {/* Dark theme — no flash needed, always charcoal */}
      <head>
        <script dangerouslySetInnerHTML={{ __html: `(function(){try{document.documentElement.setAttribute('data-theme','dark');}catch(e){}})()` }} />
      </head>
      <body suppressHydrationWarning>
        {children}
        <Analytics />
      </body>
    </html>
  );
}
