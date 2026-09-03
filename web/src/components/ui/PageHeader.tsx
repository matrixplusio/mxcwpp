export function PageHeader({ title, desc, extra }: { title: string; desc?: string; extra?: React.ReactNode }) {
  return (
    <div className="flex items-end justify-between mb-6">
      <div>
        <h1 className="text-xl font-bold text-ink">{title}</h1>
        {desc && <p className="mt-1 text-sm text-muted">{desc}</p>}
      </div>
      {extra}
    </div>
  );
}
