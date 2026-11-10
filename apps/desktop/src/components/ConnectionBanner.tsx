import { Info, TriangleAlert } from "lucide-react";
import { useServiceCore } from "../service";

/**
 * A quiet line about settings that wait for the service, or a warning when it
 * refused them, they could not be opened, or OmniHub's (Captun's earlier
 * name) could not be brought over, or when an older service had to
 * be stopped or another program answered in its place. A stopped service by
 * itself is normal (nothing is shared yet) and needs no message: every page
 * still works and Start brings it up.
 */
export function ConnectionBanner() {
  const { connection } = useServiceCore();
  if (!connection) return null;

  if (connection.settings_notice) {
    return (
      <div className="banner banner-warn" role="alert">
        <TriangleAlert size={16} aria-hidden="true" />
        <div className="banner-text">
          <strong>Your saved settings could not be opened</strong>
          <span>{connection.settings_notice}.</span>
          <span className="banner-hint">Captun started with fresh settings and kept the old file as captun.settings.unreadable.</span>
        </div>
      </div>
    );
  }
  if (connection.earlier_settings_notice) {
    return (
      <div className="banner banner-warn" role="alert">
        <TriangleAlert size={16} aria-hidden="true" />
        <div className="banner-text">
          <strong>Your settings from OmniHub could not be brought over</strong>
          <span>{connection.earlier_settings_notice}.</span>
          <span className="banner-hint">
            Captun started with fresh settings. OmniHub's file was left as it is, and Captun tries again next time it
            starts until you save settings of your own.
          </span>
        </div>
      </div>
    );
  }
  if (connection.connected && connection.config_sync_error) {
    return (
      <div className="banner banner-warn" role="alert">
        <TriangleAlert size={16} aria-hidden="true" />
        <div className="banner-text">
          <strong>Some saved changes could not be applied</strong>
          <span>{connection.config_sync_error}</span>
          <span className="banner-hint">Fix them and save again.</span>
        </div>
      </div>
    );
  }
  if (!connection.connected && connection.service_notice) {
    return (
      <div className="banner banner-warn" role="status">
        <TriangleAlert size={16} aria-hidden="true" />
        <span className="banner-text">{connection.service_notice}</span>
      </div>
    );
  }
  if (!connection.connected && connection.config_pending) {
    return (
      <div className="banner banner-info" title={connection.error ?? undefined}>
        <Info size={16} aria-hidden="true" />
        <span className="banner-text">Your changes are saved and take effect when sharing starts.</span>
      </div>
    );
  }
  return null;
}
