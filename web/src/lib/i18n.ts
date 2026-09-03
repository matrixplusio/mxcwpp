/**
 * i18n 基础设施(i18next + react-i18next)。
 *
 * 后续批次约定(convention for later batches):
 * - 每个 locale 一个嵌套 JSON(zh.json / en.json),按模块划分命名空间(namespace per module),
 *   例如 `assets.*`、`vuln.*`、`system.*`。
 * - 组件内统一用 `useTranslation()` 读取;key 用 lowerCamel,挂在模块命名空间下。
 * - 通用可复用词汇放在 `common.*`(如 common.edit / common.delete)。
 */
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import zh from "@/locales/zh.json";
import en from "@/locales/en.json";

export const LANG_KEY = "mxcwpp-lang";
export type Lang = "zh" | "en";

// SSR 阶段无 localStorage,默认中文;客户端读取持久化语言
function initialLang(): Lang {
  if (typeof window === "undefined") return "zh";
  const v = window.localStorage.getItem(LANG_KEY);
  return v === "en" ? "en" : "zh";
}

if (!i18n.isInitialized) {
  i18n.use(initReactI18next).init({
    resources: {
      zh: { translation: zh },
      en: { translation: en },
    },
    lng: initialLang(),
    fallbackLng: "zh",
    interpolation: { escapeValue: false },
  });
}

/** 切换语言并持久化到 localStorage */
export function setLang(lng: Lang) {
  i18n.changeLanguage(lng);
  if (typeof window !== "undefined") window.localStorage.setItem(LANG_KEY, lng);
}

export default i18n;
