import "./globals.css";
import { Providers } from "./providers";
export const metadata = { title: "MXCWPP" };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (<html lang="zh-CN"><body><Providers>{children}</Providers></body></html>);
}
