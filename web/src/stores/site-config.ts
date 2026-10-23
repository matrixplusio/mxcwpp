import { create } from "zustand";
interface SiteConfig { siteName: string; logo: string | null; }
interface SiteState extends SiteConfig { set: (c: Partial<SiteConfig>) => void; }
export const useSiteStore = create<SiteState>((set) => ({
  siteName: "MXCWPP", logo: null,
  set: (c) => set(c),
}));
