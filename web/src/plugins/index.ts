export { exposePluginSDK, getPluginComponent, onPluginRegistered, getRegisteredCount } from "./registry";
export { PluginPage } from "./PluginPage";
export { usePlugins, notifyDashboardPluginsChanged } from "./usePlugins";
export { PluginSlot, KNOWN_SLOT_NAMES, registerSlot, getSlotEntries, getConfigSectionNames, getConfigSectionIcons, getConfigSectionOptionCounts, useConfigSectionNames, useConfigSectionIcons, useConfigSectionOptionCounts, onSlotRegistered, unregisterPluginSlots } from "./slots";
export type { KnownSlotName, SlotMetadata } from "./slots";
export type { PluginManifest, RegisteredPlugin } from "./types";
