"use client";
import { AnimatePresence, motion } from "framer-motion";
import { X } from "lucide-react";
import { useTranslation } from "react-i18next";

interface Props {
  open: boolean;
  onClose: () => void;
  title: string;
  width?: number;
  children: React.ReactNode;
  footer?: React.ReactNode;
}

export function Modal({ open, onClose, title, width = 440, children, footer }: Props) {
  const { t } = useTranslation();
  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <motion.div
            className="absolute inset-0 bg-ink/30"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />
          <motion.div
            className="relative flex max-h-[90vh] w-full flex-col overflow-hidden rounded-card bg-surface shadow-float"
            style={{ maxWidth: width }}
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.96 }}
            transition={{ duration: 0.18 }}
          >
            <div className="flex items-center justify-between border-b border-border px-5 py-4">
              <h3 className="text-base font-semibold text-ink">{title}</h3>
              <button
                type="button"
                onClick={onClose}
                className="rounded-control p-1 text-muted transition-colors hover:bg-bg hover:text-ink"
                aria-label={t("common.close")}
              >
                <X size={18} />
              </button>
            </div>
            <div className="overflow-y-auto p-5">{children}</div>
            {footer && <div className="flex justify-end gap-2 border-t border-border px-5 py-4">{footer}</div>}
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
