import i18n from "@/lib/i18n";
import { toast } from "@/components/ui/toast";

// Copy text to clipboard and show a toast. Falls back to a hidden textarea
// when the async clipboard API is unavailable (e.g. non-secure contexts).
export async function copyText(text: string | undefined | null, label?: string): Promise<void> {
  if (!text) return;
  const t = i18n.t.bind(i18n);
  const done = () => toast.success(label ? t("common.copiedLabel", { label }) : t("common.copied"));
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      done();
      return;
    }
    throw new Error("clipboard unavailable");
  } catch {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      done();
    } catch {
      toast.error(t("common.copyFailed"));
    }
  }
}
