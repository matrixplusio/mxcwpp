"use client";
import { useState } from "react";
import { Check, Copy } from "lucide-react";

// CopyButton 复制文本到剪贴板，复制后短暂显示对勾。用于 host_id 等长标识。
export function CopyButton({ text, className = "" }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  if (!text) return null;
  return (
    <button
      type="button"
      title="复制"
      className={`inline-flex items-center text-muted transition-colors hover:text-ink ${className}`}
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      {copied ? <Check size={13} className="text-success" /> : <Copy size={13} />}
    </button>
  );
}
