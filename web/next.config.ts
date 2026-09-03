import type { NextConfig } from "next";

const API_TARGET = process.env.API_TARGET || "http://manager:8080";
const isDev = process.env.NODE_ENV !== "production";

// 生产走静态导出（next build -> out/），由 nginx 服务静态 + 反代 /api。
// 开发用 next dev 的 rewrites 代理 /api 到后端；导出模式不支持 rewrites，故仅 dev 启用。
const nextConfig: NextConfig = {
  output: "export",
  ...(isDev
    ? {
        async rewrites() {
          return [
            { source: "/api/:path*", destination: `${API_TARGET}/api/:path*` },
            { source: "/uploads/:path*", destination: `${API_TARGET}/uploads/:path*` },
          ];
        },
      }
    : {}),
};
export default nextConfig;
