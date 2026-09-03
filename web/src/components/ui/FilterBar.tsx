interface Props {
  children: React.ReactNode;
  extra?: React.ReactNode;
}

export function FilterBar({ children, extra }: Props) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      {children}
      {extra && <div className="ml-auto">{extra}</div>}
    </div>
  );
}
