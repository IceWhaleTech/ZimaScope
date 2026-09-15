/**
 * Z-Scope — local-first network observability at the device boundary.
 * Routes, providers and the data layer meet here.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HashRouter, Navigate, Route, Routes, useSearchParams } from "react-router";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AppLayout } from "@/components/app-layout";
import { DetailsProvider } from "@/hooks/use-details";
import { ThemeProvider } from "@/hooks/use-theme";
import { TopbarProvider } from "@/hooks/use-topbar";
import { useStreamResync } from "@/hooks/use-data";
import { OverviewView } from "@/views/overview";
import { ExplorerView } from "@/views/explorer";
import { SettingsView } from "@/views/settings";
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

/** Legacy scope paths (#/flows, #/endpoints, #/domains) fold into the one
    explorer route, carrying query params across so deep links stay valid. */
function ScopeRedirect({ scope }: { scope: "flows" | "endpoints" | "domains" }) {
  const [params] = useSearchParams();
  const next = new URLSearchParams(params);
  next.set("scope", scope);
  return <Navigate to={`/explore?${next.toString()}`} replace />;
}

/** Reloads REST state when the SSE stream reports a resync. */
function StreamSync() {
  useStreamResync();
  return null;
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <TopbarProvider>
          <DetailsProvider>
            <StreamSync />
            <HashRouter>
              <TooltipProvider delayDuration={300}>
                <Routes>
                  <Route element={<AppLayout />}>
                    <Route path="/" element={<Navigate to="/overview" replace />} />
                    <Route path="/overview" element={<OverviewView />} />
                    {/* One persistent table, three animated lenses. */}
                    <Route path="/explore" element={<ExplorerView />} />
                    <Route path="/flows" element={<ScopeRedirect scope="flows" />} />
                    <Route path="/endpoints" element={<ScopeRedirect scope="endpoints" />} />
                    <Route path="/domains" element={<ScopeRedirect scope="domains" />} />
                    <Route path="/settings" element={<SettingsView />} />
                    <Route path="*" element={<Navigate to="/overview" replace />} />
                  </Route>
                </Routes>
                <Toaster position="top-center" offset={{ top: 60 }} />
              </TooltipProvider>
            </HashRouter>
          </DetailsProvider>
        </TopbarProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
