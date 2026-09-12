/**
 * App layout: sidebar + sticky topbar + routed view. Handles the mobile
 * drawer, the "/" search shortcut, scroll reset and the route enter motion.
 */

import { useEffect, useRef, useState } from "react";
import { Outlet, useLocation, useNavigate } from "react-router";
import { motion } from "motion/react";
import { AppSidebar } from "@/components/app-sidebar";
import { Topbar } from "@/components/topbar";
import { DetailSheet } from "@/components/detail-sheet";

export const FOCUS_SEARCH_EVENT = "zimascope:focus-search";

export function AppLayout() {
  const [navOpen, setNavOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const mainRef = useRef<HTMLElement>(null);

  useEffect(() => {
    setNavOpen(false);
    mainRef.current?.scrollTo({ top: 0 });
    window.scrollTo({ top: 0 });
  }, [location.pathname, location.search]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement;
      if (["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName) || target.isContentEditable) return;
      if (event.key !== "/") return;
      event.preventDefault();
      if (location.pathname !== "/explore") navigate("/explore");
      window.setTimeout(() => window.dispatchEvent(new Event(FOCUS_SEARCH_EVENT)), 50);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [location.pathname, navigate]);

  return (
    <div className="min-h-svh">
      <AppSidebar open={navOpen} onClose={() => setNavOpen(false)} />
      <div className="flex min-h-svh min-w-0 flex-col lg:pl-[72px]">
        <Topbar onMenu={() => setNavOpen(true)} />
        <motion.main
          ref={mainRef}
          key={location.pathname}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.34, ease: [0.32, 0.72, 0, 1] }}
          className="w-full flex-1 px-5 py-5 sm:px-7 sm:py-6 lg:px-9"
        >
          <Outlet />
        </motion.main>
      </div>
      <DetailSheet />
    </div>
  );
}
