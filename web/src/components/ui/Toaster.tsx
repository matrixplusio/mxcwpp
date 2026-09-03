"use client";
import { AnimatePresence, motion } from "framer-motion";
import { CheckCircle, Info, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils/cn";
import { dismissToast, subscribeToasts, type ToastItem, type ToastType } from "./toast";

const icons: Record<ToastType, typeof CheckCircle> = {
  success: CheckCircle,
  error: XCircle,
  info: Info,
};
const iconColor: Record<ToastType, string> = {
  success: "text-success",
  error: "text-danger",
  info: "text-info",
};

function ToastCard({ item }: { item: ToastItem }) {
  useEffect(() => {
    const timer = setTimeout(() => dismissToast(item.id), 3000);
    return () => clearTimeout(timer);
  }, [item.id]);

  const Icon = icons[item.type];
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 24 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 24 }}
      transition={{ duration: 0.2 }}
      className="flex items-center gap-2 rounded-control border border-border bg-surface px-4 py-3 text-sm text-ink shadow-card"
    >
      <Icon size={18} className={cn("shrink-0", iconColor[item.type])} />
      <span>{item.message}</span>
    </motion.div>
  );
}

export function Toaster() {
  const [items, setItems] = useState<ToastItem[]>([]);
  useEffect(() => subscribeToasts(setItems), []);

  return (
    <div className="fixed bottom-4 right-4 z-50 space-y-2">
      <AnimatePresence>
        {items.map((item) => (
          <ToastCard key={item.id} item={item} />
        ))}
      </AnimatePresence>
    </div>
  );
}
