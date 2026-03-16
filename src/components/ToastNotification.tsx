"use client";

import { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

interface ToastNotificationProps {
  message: string;
  visible: boolean;
  onDismiss: () => void;
}

export function ToastNotification({ message, visible, onDismiss }: ToastNotificationProps) {
  useEffect(() => {
    if (!visible) return;
    const timer = setTimeout(onDismiss, 3000);
    return () => clearTimeout(timer);
  }, [visible, onDismiss]);

  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 16 }}
          transition={{ duration: 0.2 }}
          onClick={onDismiss}
          style={{
            position: "fixed",
            bottom: 32,
            left: "50%",
            transform: "translateX(-50%)",
            zIndex: 100,
            background: "var(--bg-paper)",
            border: "2.5px solid var(--border-black)",
            boxShadow: "5px 5px 0px var(--ink-black)",
            padding: "12px 24px",
            fontFamily: "var(--font-mono)",
            fontSize: "13px",
            fontWeight: 600,
            color: "var(--ink-black)",
            letterSpacing: "0.02em",
            cursor: "pointer",
            whiteSpace: "nowrap",
            userSelect: "none",
          }}
        >
          {message}
        </motion.div>
      )}
    </AnimatePresence>
  );
}
