// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "@/i18n";
import type { PluginsHubResponse } from "@/lib/api";
import PluginsPage from "./PluginsPage";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const apiMocks = vi.hoisted(() => ({
  getPluginsHub: vi.fn(),
  getMemoryProviderConfig: vi.fn(),
}));
const pageMocks = vi.hoisted(() => ({
  setAfterTitle: vi.fn(),
  showToast: vi.fn(),
}));

vi.mock("@/lib/api", () => ({ api: apiMocks }));
vi.mock("@/contexts/usePageHeader", () => ({
  usePageHeader: () => ({ setAfterTitle: pageMocks.setAfterTitle }),
}));
vi.mock("@nous-research/ui/hooks/use-toast", () => ({
  useToast: () => ({ toast: null, showToast: pageMocks.showToast }),
}));

const plugin = (
  name: string,
  label: string,
  hidden: boolean,
  slots: string[] = [],
  userHidden = false,
): PluginsHubResponse["plugins"][number] => ({
  name,
  version: "1.0.0",
  description: `${label} plugin`,
  source: "bundled",
  runtime_status: "enabled",
  has_dashboard_manifest: true,
  dashboard_manifest: {
    name,
    label,
    description: `${label} dashboard`,
    icon: "Puzzle",
    version: "1.0.0",
    tab: { path: `/${name}`, hidden },
    slots,
    entry: "dist/index.js",
    css: null,
    has_api: false,
    source: "bundled",
  },
  path: `/plugins/${name}`,
  can_remove: false,
  can_update_git: false,
  auth_required: false,
  auth_command: "",
  user_hidden: userHidden,
});

describe("Plugins page dashboard visibility controls", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    apiMocks.getPluginsHub.mockResolvedValue({
      plugins: [
        plugin("buzz-platform", "Buzz", true, ["config:section:buzz"]),
        plugin("hidden-buzz-platform", "Hidden Buzz", true, ["config:section:buzz"], true),
        plugin("standalone-dashboard", "Standalone", false),
      ],
      orphan_dashboard_plugins: [],
      providers: {
        memory_provider: "",
        memory_options: [],
        context_engine: "compressor",
        context_options: [],
      },
    } satisfies PluginsHubResponse);
    container = document.createElement("div");
    document.body.append(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    vi.clearAllMocks();
  });

  it("does not offer to hide a hidden-tab Config plugin", async () => {
    await act(async () =>
      root.render(
        <MemoryRouter>
          <I18nProvider>
            <PluginsPage />
          </I18nProvider>
        </MemoryRouter>,
      ),
    );
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });

    const visibilityButtons = Array.from(container.querySelectorAll("button")).filter(
      (button) => button.textContent?.includes("Hide from sidebar"),
    );
    expect(visibilityButtons).toHaveLength(1);
    const remainingPluginRow = visibilityButtons[0]?.parentElement?.parentElement?.textContent;
    expect(remainingPluginRow).toContain("standalone-dashboard");
    expect(remainingPluginRow).not.toContain("buzz-platform");

    const recoveryButtons = Array.from(container.querySelectorAll("button")).filter(
      (button) => button.textContent?.includes("Show in sidebar"),
    );
    expect(recoveryButtons).toHaveLength(1);
    const recoverablePluginRow = recoveryButtons[0]?.parentElement?.parentElement?.textContent;
    expect(recoverablePluginRow).toContain("hidden-buzz-platform");
  });
});
