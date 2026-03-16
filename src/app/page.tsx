"use client";

import { ModelSettings } from "@/components/ModelSettings";
import { SourceCard } from "@/components/SourceCard";
import { ToastNotification } from "@/components/ToastNotification";
import {
  detectWebGPUAvailability,
  formatWebGPUReason,
  type WebGPUAvailabilityReason,
} from "@/lib/webgpu";
import { useEffect, useState, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import {
  GitBranch,
  Shield,
  FileCode,
  Bug,
  ClipboardCheck,
  Upload,
} from "lucide-react";

const CHAT_STORAGE_PREFIX = "gitask-chat-";

const SHADOW_1 = "3px 3px 0px #000000";

const EXAMPLE_QUERIES = [
  "What ATT&CK techniques use PowerShell?",
  "Show Sigma rules for lateral movement",
  "Does CVE-2024-3400 have detection coverage?",
  "Map NIST AC-2 account management controls",
  "Find authentication vulnerabilities in this code",
];

interface SavedChatEntry {
  id: string;
  storageKey: string;
  owner: string;
  repo: string;
  chatId: string | null;
  messageCount: number;
  lastUpdated: number;
  label: string;
}

function buildChatLabel(messages: Array<{ role?: string; content?: string }>, fallback: string): string {
  const firstUserMessage = messages.find(
    (m) => m?.role === "user" && typeof m.content === "string" && m.content.trim().length > 0
  );
  if (!firstUserMessage || !firstUserMessage.content) return fallback;
  const compact = firstUserMessage.content.trim().replace(/\s+/g, " ");
  return compact.length > 36 ? `${compact.slice(0, 36)}...` : compact;
}

function parseSavedChatEntries(key: string, raw: string): SavedChatEntry[] {
  if (!key.startsWith(CHAT_STORAGE_PREFIX)) return [];
  const repoPath = key.slice(CHAT_STORAGE_PREFIX.length);
  const slashIndex = repoPath.indexOf("/");
  if (slashIndex <= 0 || slashIndex >= repoPath.length - 1) return [];

  const owner = repoPath.slice(0, slashIndex);
  const repo = repoPath.slice(slashIndex + 1);

  try {
    const parsed = JSON.parse(raw) as
      | Array<{ role?: string; content?: string }>
      | {
          activeChatId?: string;
          sessions?: Array<{
            chat_id?: string;
            title?: string;
            updatedAt?: number;
            messages?: Array<{ role?: string; content?: string }>;
          }>;
        };

    if (Array.isArray(parsed)) {
      const messages = parsed;
      if (messages.length === 0) return [];
      return [
        {
          id: `${key}::legacy`,
          storageKey: key,
          owner,
          repo,
          chatId: null,
          messageCount: messages.length,
          lastUpdated: 0,
          label: buildChatLabel(messages, "Chat 1"),
        },
      ];
    }

    if (!parsed || !Array.isArray(parsed.sessions) || parsed.sessions.length === 0) return [];
    return parsed.sessions
      .filter((session) => session && typeof session.chat_id === "string")
      .map((session, index) => {
        const messages = Array.isArray(session.messages) ? session.messages : [];
        const fallbackTitle = `Chat ${index + 1}`;
        const label =
          typeof session.title === "string" && session.title.trim().length > 0
            ? session.title
            : buildChatLabel(messages, fallbackTitle);
        return {
          id: `${key}::${session.chat_id}`,
          storageKey: key,
          owner,
          repo,
          chatId: session.chat_id ?? null,
          messageCount: messages.length,
          lastUpdated: typeof session.updatedAt === "number" ? session.updatedAt : 0,
          label,
        };
      });
  } catch {
    return [];
  }
}

export default function LandingPage() {
  const [toastMsg, setToastMsg] = useState("");
  const [toastVisible, setToastVisible] = useState(false);
  const [githubUrl, setGithubUrl] = useState("");
  const [githubError, setGithubError] = useState("");
  const [savedChats, setSavedChats] = useState<SavedChatEntry[]>([]);
  const [isHowVisible, setIsHowVisible] = useState(false);
  const [gpuSupported, setGpuSupported] = useState(true);
  const [gpuSupportReason, setGpuSupportReason] = useState<WebGPUAvailabilityReason>("ok");
  const [isMobile, setIsMobile] = useState(false);
  const howSectionRef = useRef<HTMLElement>(null);
  const sourcesRef = useRef<HTMLElement>(null);
  const router = useRouter();

  // isMobile is kept in state for potential future use; CSS grid handles responsive layout
  void isMobile;

  function showToast(msg: string) {
    setToastMsg(msg);
    setToastVisible(true);
  }

  const loadSavedChats = useCallback(() => {
    if (typeof window === "undefined") return;
    try {
      const entries: SavedChatEntry[] = [];
      for (const key of Object.keys(localStorage)) {
        if (!key.startsWith(CHAT_STORAGE_PREFIX)) continue;
        const raw = localStorage.getItem(key);
        if (!raw) continue;
        entries.push(...parseSavedChatEntries(key, raw));
      }
      entries.sort((a, b) => {
        if (a.lastUpdated !== b.lastUpdated) return b.lastUpdated - a.lastUpdated;
        return `${a.owner}/${a.repo}`.localeCompare(`${b.owner}/${b.repo}`);
      });
      setSavedChats(entries);
    } catch (e) {
      console.warn("Failed to scan local chat storage:", e);
      setSavedChats([]);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const availability = await Promise.race([
        detectWebGPUAvailability(),
        new Promise<{ supported: true; reason: "ok" }>((resolve) =>
          setTimeout(() => resolve({ supported: true, reason: "ok" }), 1500)
        ),
      ]);
      if (cancelled) return;
      setGpuSupported(availability.supported);
      setGpuSupportReason(availability.reason);
    })();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    const check = () => setIsMobile(window.innerWidth < 600);
    check();
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);

  useEffect(() => {
    const node = howSectionRef.current;
    if (!node) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) { setIsHowVisible(true); observer.disconnect(); }
      },
      { threshold: 0.22 }
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    loadSavedChats();
    const handleVisibility = () => {
      if (document.visibilityState === "visible") loadSavedChats();
    };
    window.addEventListener("focus", loadSavedChats);
    window.addEventListener("storage", loadSavedChats);
    document.addEventListener("visibilitychange", handleVisibility);
    return () => {
      window.removeEventListener("focus", loadSavedChats);
      window.removeEventListener("storage", loadSavedChats);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [loadSavedChats]);

  function handleGitHubSubmit(e?: React.SyntheticEvent) {
    e?.preventDefault();
    setGithubError("");
    const match = githubUrl.match(
      /(?:https?:\/\/)?(?:www\.)?github\.com\/([^\/]+)\/([^\/\s]+)/
    );
    if (!match) {
      setGithubError("Enter a valid GitHub URL");
      return;
    }
    const owner = match[1];
    const repo = match[2].replace(/\.git$/, "");
    router.push(`/${owner}/${repo}`);
  }

  function handleOpenSavedChat(chat: SavedChatEntry) {
    if (typeof window !== "undefined" && chat.chatId) {
      try {
        const raw = localStorage.getItem(chat.storageKey);
        if (raw) {
          const parsed = JSON.parse(raw) as { activeChatId?: string; sessions?: unknown[] };
          if (parsed && Array.isArray(parsed.sessions)) {
            localStorage.setItem(
              chat.storageKey,
              JSON.stringify({ ...parsed, activeChatId: chat.chatId })
            );
          }
        }
      } catch {
        // Ignore storage parse/write failures and continue routing.
      }
    }
    router.push(`/${chat.owner}/${chat.repo}`);
  }

  function handleDeleteSavedChat(chat: SavedChatEntry) {
    if (typeof window === "undefined") return;
    const confirmed = window.confirm("Delete local chats for this repository?");
    if (!confirmed) return;
    if (!chat.chatId) {
      localStorage.removeItem(chat.storageKey);
      loadSavedChats();
      return;
    }
    try {
      const raw = localStorage.getItem(chat.storageKey);
      if (!raw) { loadSavedChats(); return; }
      const parsed = JSON.parse(raw) as {
        activeChatId?: string;
        sessions?: Array<{ chat_id?: string; title?: string; updatedAt?: number; messages?: Array<{ role?: string; content?: string }> }>;
      };
      if (!parsed || !Array.isArray(parsed.sessions)) {
        localStorage.removeItem(chat.storageKey);
        loadSavedChats();
        return;
      }
      const nextSessions = parsed.sessions.filter((s) => s.chat_id !== chat.chatId);
      if (nextSessions.length === 0) {
        localStorage.removeItem(chat.storageKey);
      } else {
        const nextActive = nextSessions.some((s) => s.chat_id === parsed.activeChatId)
          ? parsed.activeChatId
          : nextSessions[0].chat_id;
        localStorage.setItem(chat.storageKey, JSON.stringify({ activeChatId: nextActive, sessions: nextSessions }));
      }
    } catch {
      localStorage.removeItem(chat.storageKey);
    }
    loadSavedChats();
  }

  function handleDeleteAllSavedChats() {
    if (savedChats.length === 0) return;
    if (typeof window === "undefined") return;
    const confirmed = window.confirm("Delete all local chats across repositories?");
    if (!confirmed) return;
    const keys = new Set(savedChats.map((entry) => entry.storageKey));
    for (const key of keys) localStorage.removeItem(key);
    setSavedChats([]);
  }

  function handleOpenLLMSettings() {
    if (typeof window === "undefined") return;
    window.dispatchEvent(new Event("gitask-open-llm-settings"));
  }

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-cream)", color: "var(--ink-black)", fontFamily: "var(--font-sans)" }}>

      {/* ── NAV ── */}
      <nav style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "16px 40px",
        borderBottom: "2.5px solid var(--border-black)",
        background: "var(--bg-paper)",
        position: "sticky",
        top: 0,
        zIndex: 40,
        boxShadow: SHADOW_1,
      }}>
        <span style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1.25rem", letterSpacing: "0.02em", color: "var(--ink-black)", textTransform: "uppercase" }}>
          SecAsk
        </span>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <ModelSettings />
          <a
            href="https://github.com/FloareDor/gitask"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              fontSize: "12px",
              fontWeight: 700,
              color: "var(--ink-black)",
              textDecoration: "none",
              border: "2.5px solid var(--border-black)",
              padding: "6px 14px",
              fontFamily: "var(--font-sans)",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
              boxShadow: "var(--shadow-subtle)",
            }}
          >
            GitHub ↗
          </a>
        </div>
      </nav>

      {/* ── HERO ── */}
      <section style={{
        minHeight: "78vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "80px 24px",
        textAlign: "center",
        background: "var(--bg-cream)",
      }}>
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="paper-card-hero"
          style={{ textAlign: "center" }}
        >
          {/* Status badge */}
          <div style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 8,
            padding: "6px 16px",
            border: "2px solid var(--border-black)",
            fontFamily: "var(--font-mono)",
            fontSize: "11px",
            fontWeight: 600,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: "var(--ink-medium)",
            marginBottom: 28,
            background: "var(--bg-paper-alt)",
            boxShadow: "var(--shadow-subtle)",
          }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: "#6B8F71", display: "inline-block" }} className="pulse" />
            Browser-native · No server · Keys stay local
          </div>

          <h1 style={{
            fontFamily: "var(--font-display)",
            fontSize: "clamp(2.2rem, 6vw, 4rem)",
            fontWeight: 900,
            lineHeight: 1.05,
            letterSpacing: "0.01em",
            color: "var(--ink-black)",
            marginBottom: 20,
            textTransform: "uppercase",
          }}>
            Ask your security<br />stack anything.
          </h1>

          <p style={{
            fontSize: "clamp(0.95rem, 2vw, 1.1rem)",
            color: "var(--ink-medium)",
            lineHeight: 1.65,
            maxWidth: 520,
            marginBottom: 36,
            fontFamily: "var(--font-sans)",
            margin: "0 auto 36px",
          }}>
            Index ATT&CK, Sigma rules, NVD, NIST, and your GitHub repos.
            Chat across all sources simultaneously. Embeddings, retrieval,
            and storage — all on-device.
          </p>

          {/* WebGPU warning */}
          {!gpuSupported && (
            <div style={{
              textAlign: "left",
              border: "2.5px solid var(--high-amber)",
              background: "rgba(245, 166, 35, 0.08)",
              padding: "14px 18px",
              marginBottom: 24,
              display: "flex",
              flexDirection: "column",
              gap: 8,
              boxShadow: SHADOW_1,
            }}>
              <strong style={{ fontSize: "13px", color: "var(--high-amber)", fontFamily: "var(--font-display)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                Local WebGPU inference unavailable in this browser.
              </strong>
              <p style={{ margin: 0, fontSize: "12px", color: "var(--ink-medium)", lineHeight: 1.5, fontFamily: "var(--font-sans)" }}>
                Use Gemini or Groq instead — open settings and enter your API key.
                Local indexing still works on CPU, just slower.
                {gpuSupportReason !== "ok" ? ` ${formatWebGPUReason(gpuSupportReason)}` : ""}
              </p>
              <button
                type="button"
                onClick={handleOpenLLMSettings}
                style={{
                  alignSelf: "flex-start",
                  fontSize: "12px",
                  padding: "6px 12px",
                  border: "2px solid var(--high-amber)",
                  background: "var(--high-amber)",
                  cursor: "pointer",
                  fontWeight: 700,
                  color: "var(--bg-paper)",
                  fontFamily: "var(--font-sans)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                Open Settings
              </button>
            </div>
          )}

          <a
            href="#sources"
            onClick={(e) => {
              e.preventDefault();
              sourcesRef.current?.scrollIntoView({ behavior: "smooth" });
            }}
            className="btn btn-primary"
            style={{ display: "inline-block", textDecoration: "none", fontSize: "0.9rem" }}
          >
            Get Started ↓
          </a>
        </motion.div>
      </section>

      {/* ── SOURCES ── */}
      <section
        id="sources"
        ref={sourcesRef as React.RefObject<HTMLElement>}
        style={{ padding: "72px 24px", background: "var(--bg-cream)", borderTop: "2.5px solid var(--border-black)" }}
      >
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <div className="section-heading">
            <span>Connect Your Sources</span>
          </div>

          <div className="source-grid">
            {/* GitHub Repo */}
            <SourceCard
              icon={<GitBranch size={20} strokeWidth={2} />}
              title="GitHub Repo"
              description="Index any public GitHub repository. AST chunking extracts code, docs, and structure for accurate retrieval."
              tagClass="tag-repo"
              tagLabel="REPO"
              status="idle"
              isComingSoon={false}
              hasInput={true}
              inputValue={githubUrl}
              inputPlaceholder="github.com/owner/repo"
              onInputChange={setGithubUrl}
              buttonLabel="Index Repository →"
              onAction={handleGitHubSubmit}
              animationDelay={0}
            />

            {/* ATT&CK */}
            <SourceCard
              icon={<Shield size={20} strokeWidth={2} />}
              title="MITRE ATT&CK"
              description="Index the full ATT&CK Enterprise matrix — tactics, techniques, sub-techniques, and mitigations."
              tagClass="tag-attack"
              tagLabel="ATT&CK"
              status="idle"
              isComingSoon={false}
              buttonLabel="Index ATT&CK →"
              onAction={() => router.push("/secask/attack")}
              animationDelay={0.05}
            />

            {/* Sigma */}
            <SourceCard
              icon={<FileCode size={20} strokeWidth={2} />}
              title="Sigma Rules"
              description="Load the SigmaHQ rule repository. Search detection rules by tactic, technique, or log source."
              tagClass="tag-sigma"
              tagLabel="SIGMA"
              status="idle"
              isComingSoon={false}
              buttonLabel="Index Sigma Rules →"
              onAction={() => router.push("/secask/sigma")}
              animationDelay={0.1}
            />

            {/* NVD */}
            <SourceCard
              icon={<Bug size={20} strokeWidth={2} />}
              title="NVD / CVEs"
              description="Pull recent CVE entries from NIST NVD. Ask about CVSS scores, affected products, and patch status."
              tagClass="tag-nvd"
              tagLabel="NVD"
              status="idle"
              isComingSoon={false}
              buttonLabel="Index NVD →"
              onAction={() => router.push("/secask/nvd")}
              animationDelay={0.15}
            />

            {/* NIST */}
            <SourceCard
              icon={<ClipboardCheck size={20} strokeWidth={2} />}
              title="NIST Controls"
              description="Index NIST SP 800-53 controls and NIST CSF functions. Map requirements to implementation guidance."
              tagClass="tag-compliance"
              tagLabel="NIST"
              status="idle"
              isComingSoon={false}
              buttonLabel="Index NIST →"
              onAction={() => router.push("/secask/nist")}
              animationDelay={0.2}
            />

            {/* Upload */}
            <SourceCard
              icon={<Upload size={20} strokeWidth={2} />}
              title="Upload Document"
              description="Upload a PDF, Markdown, or text file. Index custom policies, threat reports, or runbooks."
              tagClass="tag-custom"
              tagLabel="CUSTOM"
              status="idle"
              isComingSoon={false}
              hasDropZone={false}
              buttonLabel="Upload File →"
              onAction={() => router.push("/secask/custom")}
              animationDelay={0.25}
            />
          </div>

          {/* GitHub URL error */}
          {githubError && (
            <p style={{
              marginTop: 12,
              color: "var(--critical-red)",
              fontSize: "13px",
              fontFamily: "var(--font-mono)",
              padding: "8px 12px",
              background: "#FDF0EE",
              border: "2px solid var(--critical-red)",
              display: "inline-block",
            }}>
              {githubError}
            </p>
          )}
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section
        ref={howSectionRef}
        style={{
          padding: "72px 24px",
          background: "var(--bg-cream)",
          borderTop: "2.5px solid var(--border-black)",
          opacity: isHowVisible ? 1 : 0,
          transform: isHowVisible ? "translateY(0)" : "translateY(20px)",
          transition: "opacity 0.5s ease, transform 0.5s ease",
        }}
      >
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <div className="section-heading">
            <span>How It Works</span>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 0 }}>
            {[
              { num: "01", title: "Choose your sources", desc: "Connect GitHub repos, security data feeds, or upload documents. Each source is indexed independently in your browser." },
              { num: "02", title: "Indexed in your browser", desc: "AST chunking + vector embeddings run on-device via WebGPU/WASM. No data leaves your machine." },
              { num: "03", title: "Ask anything", desc: "Chat across all indexed sources simultaneously. Answers cite real chunks so you can verify every claim." },
            ].map((step, i) => (
              <motion.div
                key={step.num}
                initial={{ opacity: 0, y: 8 }}
                animate={isHowVisible ? { opacity: 1, y: 0 } : {}}
                transition={{ delay: i * 0.08, duration: 0.25 }}
                style={{
                  padding: "32px 28px",
                  border: "2.5px solid var(--border-black)",
                  borderRight: i < 2 ? "none" : "2.5px solid var(--border-black)",
                  background: "var(--bg-paper)",
                  boxShadow: i === 0 ? SHADOW_1 : "none",
                }}
              >
                <span style={{ fontFamily: "var(--font-display)", fontSize: "2.5rem", fontWeight: 900, color: "var(--ink-light)", display: "block", marginBottom: 12 }}>
                  {step.num}
                </span>
                <h3 style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1rem", marginBottom: 8, color: "var(--ink-black)", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                  {step.title}
                </h3>
                <p style={{ fontSize: "0.875rem", color: "var(--ink-medium)", lineHeight: 1.6, fontFamily: "var(--font-sans)", margin: 0 }}>
                  {step.desc}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* ── TRY AN EXAMPLE ── */}
      <section style={{ padding: "64px 24px", background: "var(--bg-cream)", borderTop: "2.5px solid var(--border-black)" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <div className="section-heading">
            <span>Try an Example</span>
          </div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {EXAMPLE_QUERIES.map((q) => {
              const domainForQuery = q.includes("ATT&CK") || q.includes("technique")
                ? "attack"
                : q.includes("Sigma") || q.includes("detection")
                ? "sigma"
                : q.includes("CVE")
                ? "nvd"
                : q.includes("NIST") || q.includes("control")
                ? "nist"
                : "attack";
              return (
                <button
                  key={q}
                  className="query-chip"
                  onClick={() => router.push(`/secask/${domainForQuery}`)}
                >
                  {q}
                </button>
              );
            })}
          </div>
        </div>
      </section>

      {/* ── RECENT CHATS ── */}
      {savedChats.length > 0 && (
        <section style={{ padding: "40px 24px", background: "var(--bg-cream)", borderTop: "2.5px solid var(--border-black)" }}>
          <div style={{ maxWidth: 1100, margin: "0 auto" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <p style={{ fontFamily: "var(--font-mono)", fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--ink-medium)", margin: 0 }}>
                Recent chats
              </p>
              <button
                onClick={handleDeleteAllSavedChats}
                style={{ fontSize: "11px", color: "var(--ink-medium)", background: "none", border: "none", cursor: "pointer", textDecoration: "underline", fontFamily: "var(--font-mono)" }}
              >
                Clear all
              </button>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {savedChats.slice(0, 5).map((chat) => (
                <div
                  key={chat.id}
                  role="button"
                  tabIndex={0}
                  onClick={() => handleOpenSavedChat(chat)}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") handleOpenSavedChat(chat); }}
                  style={{ display: "flex", alignItems: "center", gap: 12, padding: "12px 16px", background: "var(--bg-paper)", border: "2.5px solid var(--border-black)", cursor: "pointer", transition: "transform 0.1s ease, box-shadow 0.1s ease", boxShadow: "var(--shadow-subtle)" }}
                  onMouseEnter={(e) => {
                    const el = e.currentTarget as HTMLDivElement;
                    el.style.transform = "translate(-2px, -2px)";
                    el.style.boxShadow = SHADOW_1;
                  }}
                  onMouseLeave={(e) => {
                    const el = e.currentTarget as HTMLDivElement;
                    el.style.transform = "";
                    el.style.boxShadow = "var(--shadow-subtle)";
                  }}
                >
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", fontWeight: 600, color: "var(--ink-black)", flexShrink: 0 }}>
                    {chat.owner}/{chat.repo}
                  </span>
                  <span style={{ fontSize: "0.75rem", color: "var(--ink-medium)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--font-sans)" }}>
                    {chat.label} · {chat.messageCount} msg{chat.messageCount === 1 ? "" : "s"}
                  </span>
                  <button
                    onClick={(e) => { e.stopPropagation(); handleDeleteSavedChat(chat); }}
                    style={{ fontSize: "11px", color: "var(--ink-medium)", background: "none", border: "none", cursor: "pointer", flexShrink: 0, fontFamily: "var(--font-mono)" }}
                  >
                    Delete
                  </button>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* ── FOOTER ── */}
      <footer style={{ padding: "24px 40px", background: "var(--bg-paper)", borderTop: "2.5px solid var(--border-black)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontFamily: "var(--font-display)", fontWeight: 900, fontSize: "1rem", color: "var(--ink-medium)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
          SecAsk
        </span>
        <div style={{ display: "flex", gap: 16 }}>
          <a href="/ablation" style={{ fontSize: "12px", color: "var(--ink-medium)", textDecoration: "none", fontFamily: "var(--font-mono)" }}>Ablation</a>
          <a href="/metrics" style={{ fontSize: "12px", color: "var(--ink-medium)", textDecoration: "none", fontFamily: "var(--font-mono)" }}>Metrics</a>
          <a href="https://github.com/FloareDor/gitask" target="_blank" rel="noopener noreferrer" style={{ fontSize: "12px", color: "var(--ink-medium)", textDecoration: "none", fontFamily: "var(--font-mono)" }}>GitHub</a>
        </div>
      </footer>

      {/* Toast */}
      <ToastNotification
        message={toastMsg}
        visible={toastVisible}
        onDismiss={() => setToastVisible(false)}
      />
    </div>
  );
}
