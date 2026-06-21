import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "VulnScanner | AI-Powered Vulnerability Scanner & Remediation RAG",
  description: "Identify server vulnerabilities, missing headers, SQLi, and XSS issues, and receive instant, context-aware remediation codes powered by Llama 3.1 70B & RAG.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        {/* Google Fonts Import */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link 
          href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" 
          rel="stylesheet" 
        />
      </head>
      <body className="antialiased min-h-screen bg-[#07090e] text-[#f3f4f6] selection:bg-cyan-500 selection:text-black">
        {children}
      </body>
    </html>
  );
}
