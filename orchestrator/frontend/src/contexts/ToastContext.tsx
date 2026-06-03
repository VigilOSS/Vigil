// Toast notifications (UI/UX adoption wave, Tier 1a).
//
// Ported from the reference-project workbench ToastContext — the implementation is
// clean (Map of timers, cleanup on unmount, manual + auto dismiss) so the
// logic is kept verbatim. The only structural changes for our codebase:
//   - no Next.js "use client" directive (plain Vite/React build);
//   - styling is driven by our CSS vars via plain `app.css` classes instead
//     of Tailwind utilities, so toasts read correctly in both themes;
//   - a `ToastViewport` lives here so callers mount the stack once near the
//     app root (z-index 45 — above the detail-modal overlay at 40, below the
//     command palette at 50).

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { AlertCircle, CheckCircle, Info, X } from "lucide-react";

export type ToastType = "success" | "error" | "info";

export interface Toast {
  id: string;
  message: string;
  type: ToastType;
}

interface ToastContextValue {
  toast: (message: string, type?: ToastType) => void;
  toasts: Toast[];
  dismiss: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

let nextId = 0;

const AUTO_DISMISS_MS = 4000;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    const timer = timers.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timers.current.delete(id);
    }
  }, []);

  const toast = useCallback(
    (message: string, type: ToastType = "info") => {
      const id = `toast-${++nextId}`;
      setToasts((prev) => [...prev, { id, message, type }]);
      const timer = setTimeout(() => dismiss(id), AUTO_DISMISS_MS);
      timers.current.set(id, timer);
    },
    [dismiss],
  );

  // Clear every outstanding timer on unmount so we never call dismiss against
  // a torn-down provider.
  useEffect(() => {
    const map = timers.current;
    return () => {
      map.forEach((t) => clearTimeout(t));
      map.clear();
    };
  }, []);

  const value = useMemo<ToastContextValue>(
    () => ({ toast, toasts, dismiss }),
    [toast, toasts, dismiss],
  );

  return <ToastContext.Provider value={value}>{children}</ToastContext.Provider>;
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}

const TOAST_ICON: Record<ToastType, typeof Info> = {
  success: CheckCircle,
  error: AlertCircle,
  info: Info,
};

/**
 * Renders the live toast stack, fixed bottom-right. Mount once near the app
 * root, inside `ToastProvider`. Each toast gets a per-type accent (success →
 * --ok, error → --danger, info → --accent) applied via the `data-toast-type`
 * attribute the CSS keys off, plus a manual dismiss button.
 */
export function ToastViewport() {
  const { toasts, dismiss } = useToast();
  if (toasts.length === 0) return null;
  return (
    <div className="toast-viewport" role="region" aria-label="Notifications">
      {toasts.map((t) => {
        const Icon = TOAST_ICON[t.type];
        return (
          <div
            key={t.id}
            className="toast"
            data-toast-type={t.type}
            role="status"
            aria-live="polite"
          >
            <Icon className="toast-icon" size={16} aria-hidden="true" />
            <span className="toast-message">{t.message}</span>
            <button
              type="button"
              className="toast-dismiss"
              onClick={() => dismiss(t.id)}
              aria-label="Dismiss notification"
            >
              <X size={14} aria-hidden="true" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
