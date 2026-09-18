import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "LLM Firewall — Next-Gen AI Gateway & Security Operations",
  description:
    "Production-grade prompt injection security gateway with 3-layer neural scanning, RAG poisoning detection, and automated red-teaming.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
