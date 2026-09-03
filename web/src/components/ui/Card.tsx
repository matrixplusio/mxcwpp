import { cn } from "@/lib/utils/cn";
import type { HTMLAttributes } from "react";

export function Card({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-card bg-surface border border-border shadow-card transition-shadow hover:shadow-hover", className)} {...rest} />;
}
export function CardHeader({ title, extra }: { title: string; extra?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between px-5 pt-5 pb-3">
      <h3 className="text-sm font-semibold text-ink">{title}</h3>
      {extra}
    </div>
  );
}
