import nodemailer from "nodemailer";
import { prisma } from "@/lib/prisma";

let transporter: nodemailer.Transporter | null = null;

async function getTransporter() {
  if (transporter) return transporter;

  const host = process.env.SMTP_HOST;
  const port = process.env.SMTP_PORT;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (host && port && user && pass) {
    transporter = nodemailer.createTransport({
      host,
      port: parseInt(port, 10),
      secure: port === "465",
      auth: {
        user,
        pass,
      },
    });
    console.log("📨 Mailer: Initialized custom SMTP transport.");
  } else {
    console.log("📨 Mailer: No SMTP env vars found. Creating Ethereal test account...");
    try {
      const testAccount = await nodemailer.createTestAccount();
      transporter = nodemailer.createTransport({
        host: testAccount.smtp.host,
        port: testAccount.smtp.port,
        secure: testAccount.smtp.secure,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass,
        },
      });
      console.log(`📨 Mailer: Ethereal test account created successfully (${testAccount.user}).`);
    } catch (err) {
      console.error("❌ Mailer: Failed to create Ethereal test account:", err);
      throw err;
    }
  }
  return transporter;
}

export async function sendScanReportEmail(scanId: string, email: string) {
  try {
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { findings: true },
    });

    if (!scan) {
      console.error(`❌ Mailer: Scan ${scanId} not found.`);
      return;
    }

    const mailTransporter = await getTransporter();

    // Prepare JSON report matching the format in dashboard page
    const report = {
      scanId: scan.id,
      targetUrl: scan.targetUrl,
      status: scan.status,
      scannedAt: scan.createdAt,
      completedAt: scan.completedAt,
      summary: {
        totalFindings: scan.findings?.length ?? 0,
        critical: scan.findings?.filter((f) => f.severity === "CRITICAL").length ?? 0,
        high:     scan.findings?.filter((f) => f.severity === "HIGH").length ?? 0,
        medium:   scan.findings?.filter((f) => f.severity === "MEDIUM").length ?? 0,
        low:      scan.findings?.filter((f) => f.severity === "LOW").length ?? 0,
      },
      findings: scan.findings ?? [],
      generatedBy: "VulnScanner v2.0 — AI-Augmented Security Audit",
    };

    const reportContent = JSON.stringify(report, null, 2);
    const fromAddress = process.env.SMTP_FROM || 
      (process.env.SMTP_USER ? `"VulnScanner" <${process.env.SMTP_USER}>` : '"VulnScanner" <no-reply@vulnscanner.local>');

    const info = await mailTransporter.sendMail({
      from: fromAddress,
      to: email,
      subject: `🛡️ VulnScanner Audit Report: ${scan.targetUrl}`,
      text: `Hello,\n\nYour security audit for ${scan.targetUrl} has completed with status: ${scan.status}.\n\nTotal Findings: ${report.summary.totalFindings} (Critical: ${report.summary.critical}, High: ${report.summary.high}, Medium: ${report.summary.medium}, Low: ${report.summary.low})\n\nPlease find the detailed JSON audit report attached to this email.\n\nBest regards,\nThe VulnScanner Team`,
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e5e5ea; border-radius: 8px;">
          <h2 style="color: #D4380D; margin-bottom: 20px;">🛡️ VulnScanner Audit Complete</h2>
          <p>Hello,</p>
          <p>Your security scan for <strong>${scan.targetUrl}</strong> has completed with status: <span style="font-weight: bold; color: ${scan.status === "COMPLETED" ? "#27C93F" : "#FF5F56"}">${scan.status}</span>.</p>
          
          <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
            <thead>
              <tr style="background-color: #fbfbfc; border-bottom: 2px solid #e5e5ea;">
                <th style="padding: 10px; text-align: left; font-size: 14px;">Metric</th>
                <th style="padding: 10px; text-align: right; font-size: 14px;">Count</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style="padding: 10px; border-bottom: 1px solid #e5e5ea;">Total Findings</td>
                <td style="padding: 10px; border-bottom: 1px solid #e5e5ea; text-align: right; font-weight: bold;">${report.summary.totalFindings}</td>
              </tr>
              <tr style="color: #FF5F56;">
                <td style="padding: 10px; border-bottom: 1px solid #e5e5ea;">Critical</td>
                <td style="padding: 10px; border-bottom: 1px solid #e5e5ea; text-align: right; font-weight: bold;">${report.summary.critical}</td>
              </tr>
              <tr style="color: #FFBD2E;">
                <td style="padding: 10px; border-bottom: 1px solid #e5e5ea;">High</td>
                <td style="padding: 10px; border-bottom: 1px solid #e5e5ea; text-align: right; font-weight: bold;">${report.summary.high}</td>
              </tr>
              <tr style="color: #27C93F;">
                <td style="padding: 10px; border-bottom: 1px solid #e5e5ea;">Medium</td>
                <td style="padding: 10px; border-bottom: 1px solid #e5e5ea; text-align: right; font-weight: bold;">${report.summary.medium}</td>
              </tr>
              <tr style="color: #86868B;">
                <td style="padding: 10px; border-bottom: 1px solid #e5e5ea;">Low</td>
                <td style="padding: 10px; border-bottom: 1px solid #e5e5ea; text-align: right; font-weight: bold;">${report.summary.low}</td>
              </tr>
            </tbody>
          </table>

          <p>Please find the detailed vulnerability audit JSON report attached to this email.</p>
          <hr style="border: 0; border-top: 1px solid #e5e5ea; margin: 20px 0;" />
          <p style="font-size: 12px; color: #86868B;">This is an automated report from VulnScanner. Please do not reply directly to this email.</p>
        </div>
      `,
      attachments: [
        {
          filename: `vulnscan-report-${scan.id.slice(0, 8)}.json`,
          content: reportContent,
          contentType: "application/json",
        },
      ],
    });

    console.log(`📨 Mailer: Email sent successfully for scan ${scanId} to ${email}`);
    const previewUrl = nodemailer.getTestMessageUrl(info);
    if (previewUrl) {
      console.log(`🔗 Mailer: Ethereal Preview URL: ${previewUrl}`);
    }
  } catch (err) {
    console.error(`❌ Mailer: Failed to send scan report email for scan ${scanId}:`, err);
  }
}
