import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";
import { FetchGuard } from "@/components/t82/fetch-guard";
import { ThemeProvider } from "next-themes";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "DIVISION T82 — Auditoría de seguridad local-first",
  description:
    "DIVISION T82. Plataforma local-first de auditoría de postura de seguridad: solo lectura, evidencia trazable, puntuación explicable. Creado por Ramón Taboada Olivella — RTO Studio.",
  keywords: ["security", "posture assessment", "hardening", "linux", "evidence", "local-first"],
  authors: [{ name: "Ramón Taboada Olivella — RTO Studio" }],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false} disableTransitionOnChange>
          <FetchGuard />
          {children}
          <Toaster />
        </ThemeProvider>
      </body>
    </html>
  );
}
