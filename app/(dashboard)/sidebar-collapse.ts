"use client";

/**
 * Whether the desktop sidebar is folded to its icons. Remembered per browser
 * (localStorage); Ctrl+B / Cmd+B toggles it. The phone layout (sheet and
 * bottom navigation) is not affected.
 */
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";

export const SIDEBAR_WIDTH = "15.5rem";
export const SIDEBAR_WIDTH_COLLAPSED = "4rem";

const STORAGE_KEY = "mobiwaf.sidebar-collapsed";
const listeners = new Set<() => void>();

function read(): boolean {
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

let memory: boolean | null = null;

function snapshot(): boolean {
  if (memory === null) memory = read();
  return memory;
}

function write(value: boolean) {
  memory = value;
  try {
    window.localStorage.setItem(STORAGE_KEY, value ? "1" : "0");
  } catch {
    // Storage blocked: the choice lasts until the page reloads.
  }
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  const onStorage = (event: StorageEvent) => {
    if (event.key !== STORAGE_KEY) return;
    memory = null;
    listener();
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

/**
 * [collapsed, toggle, animate]; always expanded on the server render.
 * `animate` turns true on the first toggle, so the width transition runs
 * when the user folds the sidebar, not when a page loads already folded.
 */
export function useSidebarCollapsed(): [boolean, () => void, boolean] {
  const collapsed = useSyncExternalStore(subscribe, snapshot, () => false);
  const [animate, setAnimate] = useState(false);
  const toggle = useCallback(() => {
    setAnimate(true);
    write(!snapshot());
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key.toLowerCase() !== "b" || !(event.ctrlKey || event.metaKey) || event.altKey || event.shiftKey) return;
      const target = event.target as HTMLElement | null;
      if (target && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))) return;
      event.preventDefault();
      toggle();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggle]);

  return [collapsed, toggle, animate];
}
