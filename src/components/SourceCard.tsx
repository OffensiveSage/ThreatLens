"use client";

import { useRef } from "react";
import { motion } from "framer-motion";

interface SourceCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  tagClass: string;
  tagLabel: string;
  status: "idle" | "indexed" | "indexing" | "error";
  chunkCount?: number;
  isComingSoon?: boolean;
  hasInput?: boolean;
  inputValue?: string;
  inputPlaceholder?: string;
  onInputChange?: (val: string) => void;
  buttonLabel: string;
  onAction: () => void;
  animationDelay?: number;
  hasDropZone?: boolean;
}

const STATUS_COLORS: Record<string, string> = {
  idle: "var(--ink-light)",
  indexed: "var(--low-sage)",
  indexing: "var(--high-amber)",
  error: "var(--critical-red)",
};

const STATUS_LABELS: Record<string, string> = {
  idle: "Not indexed",
  indexed: "Indexed",
  indexing: "Indexing...",
  error: "Error",
};

export function SourceCard({
  icon,
  title,
  description,
  tagClass,
  tagLabel,
  status,
  chunkCount,
  isComingSoon = false,
  hasInput = false,
  inputValue = "",
  inputPlaceholder = "",
  onInputChange,
  buttonLabel,
  onAction,
  animationDelay = 0,
  hasDropZone = false,
}: SourceCardProps) {
  const cardRef = useRef<HTMLDivElement>(null);

  return (
    <motion.div
      ref={cardRef}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: animationDelay, duration: 0.25 }}
      className="paper-card source-card"
      style={{ position: "relative", overflow: "hidden" }}
      onMouseEnter={() => {
        if (cardRef.current) {
          cardRef.current.style.transform = "translate(-1px, -1px)";
          cardRef.current.style.boxShadow = "5px 5px 0px var(--ink-black)";
        }
      }}
      onMouseLeave={() => {
        if (cardRef.current) {
          cardRef.current.style.transform = "";
          cardRef.current.style.boxShadow = "var(--shadow-layer-1)";
        }
      }}
    >
      {/* Domain tag — top right */}
      <span
        className={`tag ${tagClass}`}
        style={{ position: "absolute", top: 12, right: 12 }}
      >
        {tagLabel}
      </span>

      {/* Icon + title */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6, paddingRight: 64 }}>
        <span style={{ color: "var(--info-slate)", flexShrink: 0 }}>{icon}</span>
        <h3 style={{
          fontFamily: "var(--font-display)",
          fontWeight: 900,
          fontSize: "0.95rem",
          color: "var(--ink-black)",
          textTransform: "uppercase",
          letterSpacing: "0.03em",
          margin: 0,
        }}>
          {title}
        </h3>
      </div>

      {/* Status dot */}
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 10 }}>
        <span style={{
          width: 7,
          height: 7,
          borderRadius: "50%",
          background: STATUS_COLORS[status] ?? "var(--ink-light)",
          display: "inline-block",
          flexShrink: 0,
        }} />
        <span style={{
          fontFamily: "var(--font-mono)",
          fontSize: "10px",
          color: STATUS_COLORS[status] ?? "var(--ink-light)",
          textTransform: "uppercase",
          letterSpacing: "0.08em",
          fontWeight: 600,
        }}>
          {STATUS_LABELS[status] ?? status}
          {status === "indexed" && chunkCount != null ? ` · ${chunkCount} chunks` : ""}
        </span>
      </div>

      {/* Description */}
      <p style={{
        fontSize: "0.82rem",
        color: "var(--ink-medium)",
        lineHeight: 1.55,
        fontFamily: "var(--font-sans)",
        margin: "0 0 14px 0",
      }}>
        {description}
      </p>

      {/* Optional URL input */}
      {hasInput && (
        <input
          type="text"
          className="input"
          placeholder={inputPlaceholder}
          value={inputValue}
          onChange={(e) => onInputChange?.(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") onAction(); }}
          style={{ marginBottom: 10, width: "100%", boxSizing: "border-box" }}
        />
      )}

      {/* Optional drop zone */}
      {hasDropZone && (
        <div style={{
          border: "2px dashed var(--border-black)",
          background: "var(--bg-paper-alt)",
          padding: "16px",
          textAlign: "center",
          marginBottom: 10,
          fontFamily: "var(--font-mono)",
          fontSize: "11px",
          color: "var(--ink-medium)",
          letterSpacing: "0.04em",
        }}>
          DROP FILE HERE
        </div>
      )}

      {/* Action button */}
      <button
        type="button"
        className={isComingSoon ? "btn btn-ghost" : "btn btn-primary"}
        onClick={onAction}
        style={{ width: "100%" }}
      >
        {buttonLabel}
      </button>

      {/* Coming soon overlay */}
      {isComingSoon && (
        <div style={{
          position: "absolute",
          inset: 0,
          background: "rgba(255, 253, 247, 0.6)",
          display: "flex",
          alignItems: "flex-end",
          justifyContent: "flex-start",
          padding: "12px 14px",
          pointerEvents: "none",
        }}>
          <span style={{
            fontFamily: "var(--font-mono)",
            fontSize: "9px",
            fontWeight: 700,
            color: "var(--ink-medium)",
            textTransform: "uppercase",
            letterSpacing: "0.12em",
            border: "1.5px solid var(--border-subtle)",
            padding: "2px 6px",
            background: "var(--bg-paper)",
          }}>
            Coming in Sec 5
          </span>
        </div>
      )}
    </motion.div>
  );
}
