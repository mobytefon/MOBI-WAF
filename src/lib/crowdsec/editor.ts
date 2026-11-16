/** What the proxy host editor shows about CrowdSec (src/components/proxy-hosts/editor/CrowdSecCard.tsx). */
import { isCrowdSecConfigured } from "./config";
import { getCrowdSecSettings } from "./settings";

/** The global switches, or null when CrowdSec is not configured on this instance (the card is hidden). */
export async function crowdSecEditorGlobal(): Promise<{ enabled: boolean; appliesToAll: boolean } | null> {
  if (!isCrowdSecConfigured()) return null;
  const settings = await getCrowdSecSettings();
  return { enabled: settings.enabled, appliesToAll: settings.apply_to_all_hosts };
}
