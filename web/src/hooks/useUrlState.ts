"use client";
import { useCallback, useEffect, useRef, useState } from "react";

type Primitive = string | number;

function readFromUrl<T extends Record<string, Primitive>>(defaults: T): T {
  if (typeof window === "undefined") return defaults;
  const sp = new URLSearchParams(window.location.search);
  const next = { ...defaults };
  for (const key of Object.keys(defaults) as (keyof T)[]) {
    const raw = sp.get(key as string);
    if (raw === null) continue;
    next[key] = (
      typeof defaults[key] === "number" ? Number(raw) : raw
    ) as T[keyof T];
  }
  return next;
}

function writeToUrl<T extends Record<string, Primitive>>(state: T, defaults: T): void {
  if (typeof window === "undefined") return;
  const query: Record<string, string> = {};
  for (const key of Object.keys(state) as (keyof T)[]) {
    if (state[key] === defaults[key]) continue;
    query[key as string] = String(state[key]);
  }
  const qs = new URLSearchParams(query).toString();
  const url = window.location.pathname + (qs ? `?${qs}` : "");
  window.history.replaceState(null, "", url);
}

/**
 * Sync a flat record of params to the URL query string so refresh/share/back
 * restores state. SSR-safe; does not use Next's useSearchParams.
 */
type Patch<T> = Partial<T> | ((prev: T) => Partial<T>);

export function useUrlState<T extends Record<string, Primitive>>(
  defaults: T,
): [T, (patch: Patch<T>) => void] {
  const defaultsRef = useRef(defaults);
  const [state, setStateRaw] = useState<T>(() => readFromUrl(defaultsRef.current));

  const setState = useCallback((patch: Patch<T>) => {
    setStateRaw((prev) => {
      const resolved = typeof patch === "function" ? patch(prev) : patch;
      return { ...prev, ...resolved };
    });
  }, []);

  // URL 同步放在 commit 后的 effect 中执行，避免在 render 阶段调用
  // history.replaceState 触发 Router 更新（setState-in-render 报错）。
  useEffect(() => {
    writeToUrl(state, defaultsRef.current);
  }, [state]);

  useEffect(() => {
    const onPop = () => setStateRaw(readFromUrl(defaultsRef.current));
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  return [state, setState];
}
