"use client";
import Link from "next/link";
import { cn } from "@/lib/utils/cn";

const itemBase = "h-8 px-3 rounded-[7px] text-sm transition-colors";
const containerBase = "inline-flex gap-1 p-1 rounded-control bg-surface-muted";
const activeCls = "bg-surface text-ink shadow-sm font-medium";
const inactiveCls = "text-muted hover:text-ink";

interface TabItem {
  key: string;
  label: string;
}
interface Props {
  items: TabItem[];
  active: string;
  onChange: (key: string) => void;
}

export function Tabs({ items, active, onChange }: Props) {
  return (
    <div className={containerBase}>
      {items.map((item) => (
        <button
          key={item.key}
          type="button"
          onClick={() => onChange(item.key)}
          className={cn(itemBase, item.key === active ? activeCls : inactiveCls)}
        >
          {item.label}
        </button>
      ))}
    </div>
  );
}

interface TabLinkItem {
  key: string;
  label: string;
  href: string;
}
interface TabLinkProps {
  items: TabLinkItem[];
  activeKey: string;
}

export function TabLink({ items, activeKey }: TabLinkProps) {
  return (
    <div className={containerBase}>
      {items.map((item) => (
        <Link
          key={item.key}
          href={item.href}
          className={cn(itemBase, "inline-flex items-center", item.key === activeKey ? activeCls : inactiveCls)}
        >
          {item.label}
        </Link>
      ))}
    </div>
  );
}
