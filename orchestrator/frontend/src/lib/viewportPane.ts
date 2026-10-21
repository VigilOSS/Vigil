// Viewport-bounded panes: a list or two-pane workbench that ends at the
// bottom of the viewport and scrolls inside itself, so the page never grows a
// second scrollbar on top of the list's own.

import { useLayoutEffect, useState, type DependencyList, type RefObject } from "react";

export type ViewportPane = {
  /** Pixel height that makes the anchor reach the viewport bottom; null before the first measure. */
  height: number | null;
  /** Sticky offset just below the sticky workspace header. */
  stickyTop: number;
};

/**
 * Measures where `anchor` starts on the page and returns the height that
 * makes it end at the bottom of the viewport (less the workspace panel's
 * bottom padding), never below `min` (short viewports scroll the page
 * instead). Re-measures on resize and whenever the content around the
 * anchor changes size (filters wrapping, banners appearing); pass in `deps`
 * anything else that moves it.
 */
export function useViewportPane(anchor: RefObject<HTMLElement | null>, min: number, deps: DependencyList = []): ViewportPane {
  const [layout, setLayout] = useState<ViewportPane>({ height: null, stickyTop: 0 });
  useLayoutEffect(() => {
    const measure = () => {
      const element = anchor.current;
      // Hidden behind an open record: keep the last measure.
      if (!element || typeof window === "undefined" || element.getClientRects().length === 0) return;
      const header = document.querySelector(".workspace-header");
      const headerHeight = header instanceof HTMLElement ? header.getBoundingClientRect().height : 0;
      const top = element.getBoundingClientRect().top + window.scrollY;
      const main = element.closest(".workspace-main");
      const below = main instanceof HTMLElement ? parseFloat(getComputedStyle(main).paddingBottom) || 0 : 0;
      const height = Math.max(min, Math.floor(window.innerHeight - top - below));
      const stickyTop = headerHeight + 8;
      setLayout((current) => (current.height === height && current.stickyTop === stickyTop ? current : { height, stickyTop }));
    };
    measure();
    window.addEventListener("resize", measure);
    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(measure);
    const page = anchor.current?.parentElement;
    if (observer && page) observer.observe(page);
    return () => {
      window.removeEventListener("resize", measure);
      observer?.disconnect();
    };
    // The caller lists what else moves the anchor.
  }, [anchor, min, ...deps]);
  return layout;
}
