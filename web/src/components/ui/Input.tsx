import { cn } from "@/lib/utils/cn";
import type { InputHTMLAttributes, TextareaHTMLAttributes } from "react";

const base =
  "w-full rounded-control border border-border bg-surface px-3 text-sm text-ink outline-none transition-colors focus:border-primary focus:ring-4 focus:ring-primary/10 placeholder:text-faint";

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(base, "h-10", className)} {...rest} />;
}

export function Textarea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cn(base, "min-h-20 py-2", className)} {...rest} />;
}
