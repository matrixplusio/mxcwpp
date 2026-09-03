"use client";
import { cn } from "@/lib/utils/cn";
import type { ButtonHTMLAttributes } from "react";

type Variant = "primary" | "ghost" | "danger";
interface Props extends ButtonHTMLAttributes<HTMLButtonElement> { variant?: Variant; }

const styles: Record<Variant, string> = {
  primary: "bg-primary text-white hover:bg-primary-hover",
  ghost: "bg-surface text-ink border border-border hover:bg-bg",
  danger: "bg-danger text-white hover:opacity-90",
};

export function Button({ variant = "primary", className, ...rest }: Props) {
  return (
    <button
      className={cn("inline-flex items-center justify-center gap-2 rounded-control px-4 h-9 text-sm font-medium transition-colors disabled:opacity-50", styles[variant], className)}
      {...rest}
    />
  );
}
